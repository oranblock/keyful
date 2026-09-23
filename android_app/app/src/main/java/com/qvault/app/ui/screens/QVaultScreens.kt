package com.qvault.app.ui.screens

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusDirection
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.clickable
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.*
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.qvault.app.domain.*
import com.qvault.app.ui.QVaultViewModel
import com.qvault.app.ui.components.*
import com.qvault.app.ui.print.CardPrintDocumentAdapter
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.nio.charset.StandardCharsets

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QVaultMainScreen(viewModel: QVaultViewModel) {
    val card by viewModel.card.collectAsState()
    val challenge by viewModel.challenge.collectAsState()
    val unlockState by viewModel.unlockState.collectAsState()
    val sealState by viewModel.sealState.collectAsState()
    val activeVaultName by viewModel.activeVaultName.collectAsState()
    val loadedVaultCardFp by viewModel.loadedVaultCardFp.collectAsState()
    val sealedCardFp by viewModel.sealedCardFp.collectAsState()
    val nfcScanState by viewModel.nfcScanState.collectAsState()
    val activeChallengeQr by viewModel.activeChallengeQr.collectAsState()
    val generatedResponseQr by viewModel.generatedResponseQr.collectAsState()

    var selectedTab by remember { mutableStateOf(0) }
    var focusedCellIndex by remember { mutableStateOf<Int?>(null) }
    var isSignPeerDialogOpen by remember { mutableStateOf(false) }

    val context = LocalContext.current
    val vaultsDir = remember { java.io.File(context.filesDir, "vaults").apply { mkdirs() } }
    val recoveredDir = remember { java.io.File(context.filesDir, "recovered").apply { mkdirs() } }

    // Dialogs for NFC and Wireless Ephemeral Handshake.
    // The chip cannot be opened without the card details, so they are collected first and
    // the scan prompt only appears once they are in hand.
    val hasCredentials by viewModel.hasCredentials.collectAsState()
    val awaitingCard = nfcScanState is NfcScanUiState.WaitingForCard

    if (awaitingCard && !hasCredentials) {
        CardCredentialsDialog(
            onConfirm = { accessKey, passkey -> viewModel.setCardCredentials(accessKey, passkey) },
            onCancel = { viewModel.cancelNfcScan() }
        )
    } else {
        NfcScanDialog(
            state = nfcScanState,
            onCancel = { viewModel.cancelNfcScan() }
        )
    }

    EphemeralChallengeDialog(
        challengeStr = activeChallengeQr,
        onDismiss = { viewModel.dismissEphemeralChallenge() },
        onResolve = { viewModel.resolveEphemeralResponse(it) }
    )

    GeneratedResponseQrDialog(
        responseStr = generatedResponseQr,
        onDismiss = { viewModel.dismissGeneratedResponseQr() }
    )

    SignPeerChallengeDialog(
        isOpen = isSignPeerDialogOpen,
        onDismiss = { isSignPeerDialogOpen = false },
        onSign = { challengeStr ->
            viewModel.startNfcScan(NfcAction.SIGN_CHALLENGE, challengeStr)
        }
    )

    Scaffold(
        topBar = {
            if (focusedCellIndex == null) {
                TopAppBar(
                    title = {
                        Column {
                            Text("QVault 5 Mobile", fontWeight = FontWeight.Bold)
                            if (card != null) {
                                Text(
                                    "Card ${card!!.fingerprint} • Key ${card!!.keyFingerprint}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.primary
                                )
                            } else if (sealedCardFp != null) {
                                Text(
                                    "🛡️ Sealed to Civil ID (Card $sealedCardFp)",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Color(0xFF60A5FA)
                                )
                            }
                        }
                    },
                    actions = {
                        IconButton(onClick = { viewModel.newChallenge() }) {
                            Icon(Icons.Default.Refresh, contentDescription = "New Challenge")
                        }
                        IconButton(onClick = { viewModel.wipeMemory() }) {
                            Icon(Icons.Default.Lock, contentDescription = "Wipe Memory / Lock", tint = MaterialTheme.colorScheme.error)
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                )
            }
        },
        bottomBar = {
            if (focusedCellIndex == null) {
                NavigationBar {
                    NavigationBarItem(
                        selected = selectedTab == 0,
                        onClick = { selectedTab = 0 },
                        icon = { Icon(Icons.Default.Lock, contentDescription = null) },
                        label = { Text("Unlock Vault") }
                    )
                    NavigationBarItem(
                        selected = selectedTab == 1,
                        onClick = { selectedTab = 1 },
                        icon = { Icon(Icons.Default.Add, contentDescription = null) },
                        label = { Text("Seal Vault") }
                    )
                    NavigationBarItem(
                        selected = selectedTab == 2,
                        onClick = { selectedTab = 2 },
                        icon = { Icon(Icons.AutoMirrored.Filled.List, contentDescription = null) },
                        label = { Text("Card Slips") }
                    )
                }
            }
        }
    ) { padding ->
        val effectivePadding = if (focusedCellIndex != null) PaddingValues(0.dp) else padding
        Box(modifier = Modifier.padding(effectivePadding)) {
            when (selectedTab) {
                0 -> UnlockScreen(
                    challenge = challenge,
                    unlockState = unlockState,
                    activeVaultName = activeVaultName,
                    loadedVaultCardFp = loadedVaultCardFp,
                    activeCardFp = card?.fingerprint,
                    sealedCardFp = sealedCardFp,
                    focusedCellIndex = focusedCellIndex,
                    onFocusedCellChanged = { focusedCellIndex = it },
                    onCellChanged = { idx, value -> viewModel.updateCellValue(idx, value) },
                    onLoadVault = { name, bytes -> viewModel.setLoadedVault(name, bytes) },
                    onClearVault = { viewModel.clearLoadedVault() },
                    onSaveRecovered = { payload, name -> viewModel.saveRecoveredFile(payload, name, recoveredDir) },
                    onBeginExport = { viewModel.beginRecoveredExport() },
                    onWritePendingExport = { os -> viewModel.writePendingExport(os) },
                    onCancelExport = { viewModel.cancelRecoveredExport() },
                    onUnseal = { viewModel.triggerUnseal() },
                    onNewChallenge = { viewModel.newChallenge() },
                    onTapCivilIdUnseal = { viewModel.startNfcScan(NfcAction.UNSEAL_VAULT) },
                    onStartEphemeralChallenge = { viewModel.startEphemeralChallenge() },
                    onOpenSignPeerDialog = { isSignPeerDialogOpen = true }
                )
                1 -> SealScreen(
                    card = card,
                    sealedCardFp = sealedCardFp,
                    sealState = sealState,
                    onSealText = { text, burn -> viewModel.sealText(text, vaultsDir, burn) },
                    onSealTextStream = { text, os, burn -> viewModel.sealTextToStream(text, os, burn) },
                    onSealFile = { bytes, name, burn -> viewModel.sealFile(bytes, name, vaultsDir, burn) },
                    onSealFileStream = { bytes, name, os, burn -> viewModel.sealFileToStream(bytes, name, os, burn) },
                    onSealWithCivilId = { bytes, type, name, os ->
                        viewModel.sealWithCivilId(bytes, type, name, if (os == null) vaultsDir else null, os)
                    },
                    onRestoreCardToRam = { viewModel.restoreCardToRam() },
                    onTestUnseal = { name, bytes ->
                        viewModel.setLoadedVault(name, bytes)
                        selectedTab = 0
                    },
                    onGoToCardSlips = { selectedTab = 2 }
                )
                2 -> CardSlipsScreen(
                    card = card,
                    sealedCardFp = sealedCardFp,
                    onRegenerate = { viewModel.generateNewCard() },
                    onBurnCard = { viewModel.burnCard() },
                    onRestoreCardToRam = { viewModel.restoreCardToRam() },
                    onPrintCard = { card?.let { CardPrintDocumentAdapter.printCard(context, it) } },
                    onSealToCivilId = { viewModel.startNfcScan(NfcAction.SEAL_CARD) },
                    onDeleteSealedCard = { viewModel.deleteSealedCard(context.filesDir) }
                )
            }
        }
    }
}

@Composable
fun UnlockScreen(
    challenge: List<ChallengeItem>,
    unlockState: UnlockState,
    activeVaultName: String?,
    loadedVaultCardFp: String?,
    activeCardFp: String?,
    sealedCardFp: String?,
    focusedCellIndex: Int?,
    onFocusedCellChanged: (Int?) -> Unit,
    onCellChanged: (Int, String) -> Unit,
    onLoadVault: (String, ByteArray) -> Unit,
    onClearVault: () -> Unit,
    onSaveRecovered: (ByteArray, String) -> String,
    onBeginExport: () -> Boolean,
    onWritePendingExport: (java.io.OutputStream) -> Boolean,
    onCancelExport: () -> Unit,
    onUnseal: () -> Unit,
    onNewChallenge: () -> Unit,
    onTapCivilIdUnseal: () -> Unit,
    onStartEphemeralChallenge: () -> Unit,
    onOpenSignPeerDialog: () -> Unit
) {
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current
    val coroutineScope = rememberCoroutineScope()
    var copiedTimer by remember { mutableStateOf(false) }
    var savedPath by remember { mutableStateOf<String?>(null) }
    var isGlobalRevealed by remember { mutableStateOf(false) }
    val filledCount = challenge.count { it.value.length == 4 && it.isValid }

    BackHandler(enabled = focusedCellIndex != null) {
        onFocusedCellChanged(null)
    }

    LaunchedEffect(unlockState) {
        if (unlockState is UnlockState.Success) {
            onFocusedCellChanged(null)
        }
    }

    val filePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            val name = getFileName(context, it) ?: "vault.qv5"
            val bytes = context.contentResolver.openInputStream(it)?.use { s -> s.readBytes() }
            if (bytes != null) {
                onLoadVault(name, bytes)
            }
        }
    }

    val exportRecoveredLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri: Uri? ->
        if (uri == null) {
            // User cancelled the picker; drop the snapshotted payload.
            onCancelExport()
        } else {
            // The picker backgrounded the app, so the live unlockState may have been
            // wiped by the security purge. Write the snapshot taken before launch.
            try {
                val os = context.contentResolver.openOutputStream(uri)
                if (os == null) {
                    onCancelExport()
                    savedPath = "Export failed: could not open destination"
                } else {
                    savedPath = if (onWritePendingExport(os)) {
                        "Exported via SAF successfully"
                    } else {
                        "Export failed: nothing to write (unlock again, then export)"
                    }
                }
            } catch (e: Exception) {
                onCancelExport()
                savedPath = "Export failed: ${e.message}"
            }
        }
    }

    if (focusedCellIndex != null) {
        val activeIndex = focusedCellIndex
        val currentItem = challenge.getOrNull(activeIndex)
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.background)
                .statusBarsPadding(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Minimal top row: just discrete close and progress
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(
                    onClick = { onFocusedCellChanged(null) },
                    modifier = Modifier.size(36.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Exit to Grid",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                        modifier = Modifier.size(20.dp)
                    )
                }

                Text(
                    text = "${activeIndex + 1} / ${challenge.size}",
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                )
            }

            // Center Area: Big Coordinate & 4 Large OTP Boxes
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp),
                contentAlignment = Alignment.Center
            ) {
                if (currentItem != null) {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = currentItem.coord.label,
                            fontSize = 32.sp,
                            fontWeight = FontWeight.Black,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.primary,
                            letterSpacing = 2.sp
                        )

                        Spacer(modifier = Modifier.height(20.dp))

                        // 4 Large Character Boxes
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterHorizontally),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            for (pos in 0 until 4) {
                                val char = currentItem.value.getOrNull(pos)
                                val isActiveCursor = (pos == currentItem.value.length && currentItem.value.length < 4)
                                val isFilled = char != null

                                val boxBorder = when {
                                    isActiveCursor -> BorderStroke(2.5.dp, MaterialTheme.colorScheme.primary)
                                    isFilled -> BorderStroke(1.5.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.6f))
                                    else -> BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.2f))
                                }

                                val boxBg = when {
                                    isActiveCursor -> MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f)
                                    isFilled -> MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
                                    else -> MaterialTheme.colorScheme.surfaceContainerLow
                                }

                                val displayChar = when {
                                    char == null -> if (isActiveCursor) "" else "—"
                                    isGlobalRevealed -> char.toString()
                                    else -> "●"
                                }

                                Surface(
                                    modifier = Modifier
                                        .width(66.dp)
                                        .height(78.dp),
                                    shape = RoundedCornerShape(16.dp),
                                    border = boxBorder,
                                    color = boxBg,
                                    shadowElevation = if (isActiveCursor) 4.dp else 0.dp
                                ) {
                                    Box(
                                        contentAlignment = Alignment.Center,
                                        modifier = Modifier.fillMaxSize()
                                    ) {
                                        if (isActiveCursor && char == null) {
                                            Box(
                                                modifier = Modifier
                                                    .width(2.5.dp)
                                                    .height(32.dp)
                                                    .background(MaterialTheme.colorScheme.primary, RoundedCornerShape(1.dp))
                                            )
                                        } else {
                                            Text(
                                                text = displayChar,
                                                fontSize = if (isGlobalRevealed || char == null) 30.sp else 34.sp,
                                                fontWeight = FontWeight.Bold,
                                                fontFamily = FontFamily.Monospace,
                                                color = when {
                                                    char == null -> Color.Gray.copy(alpha = 0.4f)
                                                    isGlobalRevealed -> MaterialTheme.colorScheme.onSurface
                                                    else -> MaterialTheme.colorScheme.primary
                                                }
                                            )
                                        }
                                    }
                                }
                            }
                        }

                        // Prominent Unseal button if all 15 cells are completed!
                        if (filledCount == 15) {
                            Spacer(modifier = Modifier.height(20.dp))
                            Button(
                                onClick = onUnseal,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(48.dp),
                                shape = RoundedCornerShape(12.dp),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = Color(0xFF2E7D32),
                                    contentColor = Color.White
                                )
                            ) {
                                Icon(Icons.Default.LockOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    "🔓 All 15 Entered — Unseal Vault Now",
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 14.sp
                                )
                            }
                        }
                    }
                }
            }

            // Docked Keypad at bottom
            SecureBase32Keypad(
                activeCellIndex = activeIndex,
                totalCells = challenge.size,
                onKeyTap = { char ->
                    val current = challenge.getOrNull(activeIndex)?.value ?: ""
                    if (current.length < QVaultEngine.CELL_LEN) {
                        val updated = current + char
                        onCellChanged(activeIndex, updated)
                        if (updated.length == QVaultEngine.CELL_LEN && activeIndex < challenge.size - 1) {
                            onFocusedCellChanged(activeIndex + 1)
                        }
                    }
                },
                onBackspace = {
                    val current = challenge.getOrNull(activeIndex)?.value ?: ""
                    if (current.isNotEmpty()) {
                        onCellChanged(activeIndex, current.dropLast(1))
                    } else if (activeIndex > 0) {
                        onFocusedCellChanged(activeIndex - 1)
                        val prev = challenge.getOrNull(activeIndex - 1)?.value ?: ""
                        if (prev.isNotEmpty()) {
                            onCellChanged(activeIndex - 1, prev.dropLast(1))
                        }
                    }
                },
                onClearCell = {
                    onCellChanged(activeIndex, "")
                },
                onPrevCell = {
                    if (activeIndex > 0) onFocusedCellChanged(activeIndex - 1)
                },
                onNextCell = {
                    if (activeIndex < challenge.size - 1) onFocusedCellChanged(activeIndex + 1)
                }
            )
        }
    } else {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 8.dp, vertical = 6.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
        // Vault File Picker Bar
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = if (activeVaultName != null) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant
            )
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            if (activeVaultName != null) "Vault: $activeVaultName" else "No Vault Loaded (Card Verify Only)",
                            fontWeight = FontWeight.Bold,
                            style = MaterialTheme.typography.titleSmall
                        )
                        if (activeVaultName != null) {
                            if (unlockState is UnlockState.Success) {
                                Text(
                                    "✓ Vault Decrypted Successfully",
                                    style = MaterialTheme.typography.bodySmall,
                                    fontWeight = FontWeight.Bold,
                                    color = Color(0xFF2E7D32)
                                )
                            } else if (loadedVaultCardFp != null) {
                                val matchesRam = activeCardFp != null && loadedVaultCardFp == activeCardFp
                                val matchesSealed = sealedCardFp != null && loadedVaultCardFp == sealedCardFp
                                val match = matchesRam || matchesSealed
                                val label = if (matchesRam) {
                                    "Sealed with Active Card: $loadedVaultCardFp ✓"
                                } else if (matchesSealed) {
                                    "Sealed with Civil ID Card: $loadedVaultCardFp ✓ (Tap Civil ID to Unseal)"
                                } else {
                                    "Sealed with Card: $loadedVaultCardFp ⚠️ (Requires Card $loadedVaultCardFp)"
                                }
                                Text(
                                    label,
                                    style = MaterialTheme.typography.bodySmall,
                                    fontWeight = FontWeight.SemiBold,
                                    color = if (match) Color(0xFF2E7D32) else MaterialTheme.colorScheme.error
                                )
                            } else {
                                Text(
                                    "Ready to decrypt with 15 cells",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Color.Gray
                                )
                            }
                        } else {
                            Text(
                                "Tap 'Pick .qv5' to decrypt a file, or verify key",
                                style = MaterialTheme.typography.bodySmall,
                                color = Color.Gray
                            )
                        }
                    }
                    Row {
                        Button(
                            onClick = { filePicker.launch("*/*") },
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                        ) {
                            Icon(Icons.Default.FolderOpen, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(if (activeVaultName != null) "Change" else "Pick .qv5", fontSize = 12.sp)
                        }
                        if (activeVaultName != null) {
                            Spacer(modifier = Modifier.width(4.dp))
                            IconButton(onClick = onClearVault) {
                                Icon(Icons.Default.Close, contentDescription = "Clear Vault")
                            }
                        }
                    }
                }
            }
        }

        // Civil ID Hardware Quick-Unseal Banner (Zero Typing)
        if (sealedCardFp != null && activeVaultName != null && unlockState !is UnlockState.Success) {
            Spacer(modifier = Modifier.height(6.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = Color(0xFF1E3A8A).copy(alpha = 0.22f)
                ),
                border = BorderStroke(1.5.dp, Color(0xFF3B82F6)),
                shape = RoundedCornerShape(12.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.Contactless,
                                contentDescription = null,
                                tint = Color(0xFF60A5FA),
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                "Civil ID Hardware Quick-Unseal",
                                fontWeight = FontWeight.Bold,
                                color = Color(0xFF60A5FA),
                                fontSize = 13.sp
                            )
                        }
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            "Card $sealedCardFp is sealed to this phone. Tap physical Civil ID NFC to unseal without typing.",
                            fontSize = 11.sp,
                            color = Color.LightGray
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Button(
                        onClick = onTapCivilIdUnseal,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color(0xFF2563EB),
                            contentColor = Color.White
                        ),
                        shape = RoundedCornerShape(8.dp),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                    ) {
                        Text("Tap ID", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    }
                }
            }
        }

        // Wireless Ephemeral QR Handshake Row (Single-use, anti-copying)
        Spacer(modifier = Modifier.height(6.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedButton(
                onClick = onStartEphemeralChallenge,
                modifier = Modifier.weight(1f),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 6.dp)
            ) {
                Icon(Icons.Default.QrCode, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(4.dp))
                Text("Challenge QR", fontSize = 12.sp)
            }
            OutlinedButton(
                onClick = onOpenSignPeerDialog,
                modifier = Modifier.weight(1f),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 6.dp)
            ) {
                Icon(Icons.Default.Edit, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(4.dp))
                Text("Sign Peer QR", fontSize = 12.sp)
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // Quick Actions: New Challenge and Clear Loaded
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedButton(
                onClick = onNewChallenge,
                modifier = Modifier.weight(1f),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 6.dp)
            ) {
                Icon(Icons.Default.Refresh, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(4.dp))
                Text("New Challenge", fontSize = 12.sp)
            }
            if (activeVaultName != null) {
                OutlinedButton(
                    onClick = onClearVault,
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 6.dp)
                ) {
                    Icon(Icons.Default.Clear, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Clear Vault", fontSize = 12.sp)
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        // State Feedback Banner
        AnimatedVisibility(
            visible = unlockState !is UnlockState.Idle,
            enter = fadeIn() + expandVertically(),
            exit = fadeOut() + shrinkVertically()
        ) {
            when (unlockState) {
                is UnlockState.Verifying -> {
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                }
                is UnlockState.Success -> {
                    ElevatedCard(
                        modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                        colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer)
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Check, contentDescription = null, tint = Color(0xFF2E7D32))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    "Decrypted • Key: ${unlockState.masterKeyFp}",
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.onTertiaryContainer
                                )
                            }
                            Spacer(modifier = Modifier.height(8.dp))

                            if (unlockState.metaType == "text") {
                                val textMsg = String(unlockState.payload, StandardCharsets.UTF_8).trimEnd('\u0000')
                                Surface(
                                    color = MaterialTheme.colorScheme.surface,
                                    shape = RoundedCornerShape(8.dp),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Text(
                                        textMsg,
                                        modifier = Modifier.padding(10.dp),
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 13.sp
                                    )
                                }
                                Spacer(modifier = Modifier.height(8.dp))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Button(
                                        onClick = {
                                            clipboardManager.setText(AnnotatedString(textMsg))
                                            copiedTimer = true
                                            coroutineScope.launch {
                                                delay(30_000)
                                                clipboardManager.setText(AnnotatedString(""))
                                                copiedTimer = false
                                            }
                                        }
                                    ) {
                                        Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(14.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text(if (copiedTimer) "Copied (clears in 30s)" else "Copy (auto-clears 30s)", fontSize = 11.sp)
                                    }
                                    OutlinedButton(onClick = onClearVault) {
                                        Text("Hide Plaintext", fontSize = 11.sp)
                                    }
                                }
                            } else {
                                val fname = unlockState.metaName ?: "recovered_file"
                                Text("File: $fname (${unlockState.payload.size} bytes)", style = MaterialTheme.typography.bodyMedium)
                                Spacer(modifier = Modifier.height(6.dp))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    Button(
                                        onClick = {
                                            // Snapshot the payload BEFORE the picker backgrounds
                                            // the app and the security purge wipes unlockState.
                                            if (onBeginExport()) {
                                                exportRecoveredLauncher.launch(fname)
                                            } else {
                                                savedPath = "Nothing to export — unlock the vault again."
                                            }
                                        },
                                        modifier = Modifier.weight(1f)
                                    ) {
                                        Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(16.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text("Export (SAF)", fontSize = 12.sp)
                                    }
                                    OutlinedButton(
                                        onClick = {
                                            savedPath = onSaveRecovered(unlockState.payload, fname)
                                        },
                                        modifier = Modifier.weight(1f)
                                    ) {
                                        Icon(Icons.Default.Folder, contentDescription = null, modifier = Modifier.size(16.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text("App Storage", fontSize = 12.sp)
                                    }
                                }
                                savedPath?.let {
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text("Saved: $it", color = Color(0xFF2E7D32), fontSize = 11.sp)
                                }
                            }
                        }
                    }
                }
                is UnlockState.TypoDetected -> {
                    Surface(
                        color = MaterialTheme.colorScheme.errorContainer,
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp)
                    ) {
                        Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Warning, contentDescription = null, tint = MaterialTheme.colorScheme.error)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(unlockState.message, color = MaterialTheme.colorScheme.onErrorContainer)
                        }
                    }
                }
                is UnlockState.Error -> {
                    Text(unlockState.message, color = MaterialTheme.colorScheme.error)
                }
                else -> {}
            }
        }

        // 15 Interactive Cell Boxes Grid Header
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 4.dp, vertical = 2.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "15 Challenge Cells ($filledCount/15)",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )
            Row(
                modifier = Modifier.clickable { isGlobalRevealed = !isGlobalRevealed },
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = if (isGlobalRevealed) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.secondary,
                    modifier = Modifier.size(15.dp)
                )
                Spacer(modifier = Modifier.width(4.dp))
                Text(
                    if (isGlobalRevealed) "Mask All (••••)" else "Reveal All",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.secondary
                )
            }
        }

        // 15 Interactive Cell Boxes Grid
        LazyVerticalGrid(
            columns = GridCells.Fixed(3),
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            itemsIndexed(challenge) { index, item ->
                SecureCellInputCard(
                    index = index + 1,
                    coordinate = item.coord.label,
                    value = item.value,
                    isValid = item.isValid,
                    isSelected = false,
                    isGlobalRevealed = isGlobalRevealed,
                    onClick = { onFocusedCellChanged(index) }
                )
            }
        }

        Spacer(modifier = Modifier.height(6.dp))

        // Action Buttons: Type Cells (Open Keypad) + Unseal
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = {
                    val firstUnfilled = challenge.indexOfFirst { it.value.length < 4 }
                    onFocusedCellChanged(if (firstUnfilled != -1) firstUnfilled else 0)
                },
                modifier = Modifier
                    .weight(1f)
                    .height(46.dp),
                shape = RoundedCornerShape(10.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.secondaryContainer,
                    contentColor = MaterialTheme.colorScheme.onSecondaryContainer
                )
            ) {
                Icon(Icons.Default.Keyboard, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Type Cells", fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
            }

            Button(
                onClick = onUnseal,
                enabled = true,
                modifier = Modifier
                    .weight(1f)
                    .height(46.dp),
                shape = RoundedCornerShape(10.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (filledCount == 15) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant,
                    contentColor = if (filledCount == 15) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurfaceVariant
                )
            ) {
                Icon(
                    if (filledCount == 15) Icons.Default.LockOpen else Icons.Default.Lock,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    if (filledCount == 15) {
                        if (activeVaultName != null) "🔓 Unseal Vault" else "🔓 Verify Key"
                    } else {
                        "Unseal ($filledCount/15)"
                    },
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp
                )
            }
        }
    }
}
}

@Composable
fun SealScreen(
    card: VaultCard?,
    sealedCardFp: String? = null,
    sealState: SealState,
    onSealText: (String, Boolean) -> Unit,
    onSealTextStream: (String, java.io.OutputStream, Boolean) -> Unit,
    onSealFile: (ByteArray, String, Boolean) -> Unit,
    onSealFileStream: (ByteArray, String, java.io.OutputStream, Boolean) -> Unit,
    onSealWithCivilId: ((ByteArray, String, String?, java.io.OutputStream?) -> Unit)? = null,
    onRestoreCardToRam: (() -> Unit)? = null,
    onTestUnseal: ((String, ByteArray) -> Unit)? = null,
    onGoToCardSlips: (() -> Unit)? = null
) {
    if (card == null && sealedCardFp == null) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Icon(
                imageVector = Icons.Default.Warning,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.secondary,
                modifier = Modifier.size(56.dp)
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                "No Paper Card in Memory",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                "To encrypt a new secret vault, generate a paper card in the Card Slips tab. You can enable 'One-shot Seal & Burn' to wipe it immediately after sealing.",
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(20.dp))
            Button(onClick = { onGoToCardSlips?.invoke() }) {
                Icon(Icons.AutoMirrored.Filled.List, contentDescription = null)
                Spacer(modifier = Modifier.width(8.dp))
                Text("Go to Card Slips")
            }
        }
        return
    }

    val context = LocalContext.current
    var secretText by remember { mutableStateOf("") }
    var selectedFileUri by remember { mutableStateOf<Uri?>(null) }
    var selectedFileName by remember { mutableStateOf<String?>(null) }
    var selectedFileBytes by remember { mutableStateOf<ByteArray?>(null) }
    var burnAfterSeal by remember { mutableStateOf(false) }

    val filePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            selectedFileUri = it
            selectedFileName = getFileName(context, it) ?: "file.bin"
            selectedFileBytes = context.contentResolver.openInputStream(it)?.use { s -> s.readBytes() }
        }
    }

    val exportTextLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri: Uri? ->
        uri?.let {
            try {
                context.contentResolver.openOutputStream(it)?.let { os ->
                    val civilIdSeal = onSealWithCivilId
                    if (card != null) {
                        onSealTextStream(secretText, os, burnAfterSeal)
                    } else if (sealedCardFp != null && civilIdSeal != null) {
                        civilIdSeal(secretText.toByteArray(StandardCharsets.UTF_8), "text", "secret_message.qv5", os)
                    } else {
                        try { os.close() } catch (_: Exception) {}
                    }
                }
            } catch (e: Exception) {}
        }
    }

    val exportFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri: Uri? ->
        uri?.let {
            try {
                val bytes = selectedFileBytes ?: return@let
                val name = selectedFileName ?: "file"
                context.contentResolver.openOutputStream(it)?.let { os ->
                    val civilIdSeal = onSealWithCivilId
                    if (card != null) {
                        onSealFileStream(bytes, name, os, burnAfterSeal)
                    } else if (sealedCardFp != null && civilIdSeal != null) {
                        civilIdSeal(bytes, "file", name, os)
                    } else {
                        try { os.close() } catch (_: Exception) {}
                    }
                }
            } catch (e: Exception) {}
        }
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Text("Seal Secret Vault", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            Text("Encrypt messages or files into AES-256-GCM .qv5 vaults using your card.", style = MaterialTheme.typography.bodySmall, color = Color.Gray)
        }

        // Active Card & One-shot Seal & Burn option
        item {
            if (card != null) {
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("Active Card: ${card.fingerprint}", fontWeight = FontWeight.Bold)
                            Text("Key: ${card.keyFingerprint}", fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                        }
                        Spacer(modifier = Modifier.height(10.dp))
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Switch(
                                checked = burnAfterSeal,
                                onCheckedChange = { burnAfterSeal = it }
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Column {
                                Text("One-shot Seal & Burn", fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                                Text("Automatically wipe card from phone RAM after sealing completes", fontSize = 11.sp, color = Color.Gray)
                            }
                        }
                    }
                }
            } else if (sealedCardFp != null) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF1E3A8A).copy(alpha = 0.22f)),
                    border = BorderStroke(1.5.dp, Color(0xFF3B82F6)),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Shield, contentDescription = null, tint = Color(0xFF60A5FA), modifier = Modifier.size(24.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Column {
                                Text("Civil ID Hardware Card Active", fontWeight = FontWeight.Bold, color = Color(0xFF60A5FA), fontSize = 14.sp)
                                Text("Bound Card: $sealedCardFp", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                            }
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            "Encrypt directly using your physical Civil ID card, or tap below to restore the full card into RAM.",
                            fontSize = 11.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.height(10.dp))
                        OutlinedButton(
                            onClick = { onRestoreCardToRam?.invoke() },
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFF93C5FD)),
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                        ) {
                            Icon(Icons.Default.Contactless, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Restore Card to RAM (Tap Civil ID)", fontSize = 11.sp)
                        }
                    }
                }
            }
        }

        // Feedback Banner
        item {
            AnimatedVisibility(visible = sealState !is SealState.Idle) {
                when (sealState) {
                    is SealState.Sealing -> LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    is SealState.Success -> {
                        Surface(
                            color = MaterialTheme.colorScheme.tertiaryContainer,
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Check, contentDescription = null, tint = Color(0xFF2E7D32))
                                Spacer(modifier = Modifier.width(8.dp))
                                Column {
                                    Text(sealState.message, fontWeight = FontWeight.Bold)
                                    Text("Location: ${sealState.fileName}", fontSize = 11.sp)
                                    Spacer(modifier = Modifier.height(6.dp))
                                    Button(
                                        onClick = {
                                            try {
                                                val f = java.io.File(sealState.fileName)
                                                if (f.exists()) {
                                                    onTestUnseal?.invoke(f.name, f.readBytes())
                                                }
                                            } catch (e: Exception) {}
                                        },
                                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                                    ) {
                                        Icon(Icons.Default.LockOpen, contentDescription = null, modifier = Modifier.size(16.dp))
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text("Test Unseal in Unlock Tab", fontSize = 12.sp)
                                    }
                                }
                            }
                        }
                    }
                    is SealState.Error -> {
                        Text(sealState.message, color = MaterialTheme.colorScheme.error)
                    }
                    else -> {}
                }
            }
        }

        // Section 1: Seal Text Message
        item {
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("1. Seal Secret Text Message", fontWeight = FontWeight.Bold)
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = secretText,
                        onValueChange = { secretText = it },
                        label = { Text("Message to seal") },
                        modifier = Modifier.fillMaxWidth().height(110.dp)
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        if (card != null) {
                            Button(
                                onClick = {
                                    if (secretText.isNotBlank()) {
                                        exportTextLauncher.launch("secret_message.qv5")
                                    }
                                },
                                modifier = Modifier.weight(1f),
                                enabled = secretText.isNotBlank()
                            ) {
                                Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Export (SAF)", fontSize = 12.sp)
                            }
                            OutlinedButton(
                                onClick = {
                                    if (secretText.isNotBlank()) {
                                        onSealText(secretText, burnAfterSeal)
                                    }
                                },
                                modifier = Modifier.weight(1f),
                                enabled = secretText.isNotBlank()
                            ) {
                                Icon(Icons.Default.Folder, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("App Storage", fontSize = 12.sp)
                            }
                        } else {
                            Button(
                                onClick = {
                                    if (secretText.isNotBlank()) {
                                        onSealWithCivilId?.invoke(secretText.toByteArray(StandardCharsets.UTF_8), "text", null, null)
                                    }
                                },
                                modifier = Modifier.weight(1f),
                                enabled = secretText.isNotBlank(),
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2563EB))
                            ) {
                                Icon(Icons.Default.Contactless, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Seal with Civil ID", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                            }
                            OutlinedButton(
                                onClick = {
                                    if (secretText.isNotBlank()) {
                                        exportTextLauncher.launch("secret_message.qv5")
                                    }
                                },
                                modifier = Modifier.weight(1f),
                                enabled = secretText.isNotBlank()
                            ) {
                                Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Export (SAF)", fontSize = 12.sp)
                            }
                        }
                    }
                }
            }
        }

        // Section 2: Seal Any File from Phone
        item {
            ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("2. Seal File from Phone", fontWeight = FontWeight.Bold)
                    Spacer(modifier = Modifier.height(8.dp))

                    OutlinedButton(
                        onClick = { filePicker.launch("*/*") },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.AttachFile, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(selectedFileName?.let { "Selected: $it" } ?: "Select File to Seal")
                    }

                    selectedFileBytes?.let { bytes ->
                        Spacer(modifier = Modifier.height(6.dp))
                        Text("Size: ${bytes.size} bytes", fontSize = 12.sp, color = Color.Gray)
                        Spacer(modifier = Modifier.height(8.dp))
                        val name = selectedFileName ?: "file"
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            if (card != null) {
                                Button(
                                    onClick = {
                                        exportFileLauncher.launch("${name}.qv5")
                                    },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("Export (SAF)", fontSize = 12.sp)
                                }
                                OutlinedButton(
                                    onClick = {
                                        onSealFile(bytes, name, burnAfterSeal)
                                    },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(Icons.Default.Folder, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("App Storage", fontSize = 12.sp)
                                }
                            } else {
                                Button(
                                    onClick = {
                                        onSealWithCivilId?.invoke(bytes, "file", name, null)
                                    },
                                    modifier = Modifier.weight(1f),
                                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2563EB))
                                ) {
                                    Icon(Icons.Default.Contactless, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("Seal with Civil ID", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                                }
                                OutlinedButton(
                                    onClick = {
                                        exportFileLauncher.launch("${name}.qv5")
                                    },
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("Export (SAF)", fontSize = 12.sp)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun SecureCellInputCard(
    index: Int,
    coordinate: String,
    value: String,
    isValid: Boolean,
    isSelected: Boolean,
    isGlobalRevealed: Boolean,
    onClick: () -> Unit
) {
    var isLocallyRevealed by remember { mutableStateOf(false) }
    val showPlaintext = isGlobalRevealed || isLocallyRevealed

    OutlinedCard(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(10.dp),
        border = if (isSelected) {
            BorderStroke(2.dp, MaterialTheme.colorScheme.primary)
        } else if (isValid) {
            BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant)
        } else {
            BorderStroke(0.75.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
        },
        colors = CardDefaults.outlinedCardColors(
            containerColor = when {
                isSelected -> MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.35f)
                isValid -> MaterialTheme.colorScheme.surface
                else -> MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
            }
        )
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 6.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("#$index", fontSize = 10.sp, color = MaterialTheme.colorScheme.secondary)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        coordinate,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = if (isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface
                    )
                    if (value.isNotEmpty()) {
                        Spacer(modifier = Modifier.width(3.dp))
                        Icon(
                            imageVector = if (showPlaintext) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                            contentDescription = if (showPlaintext) "Mask cell" else "Reveal cell",
                            tint = MaterialTheme.colorScheme.secondary,
                            modifier = Modifier
                                .size(13.dp)
                                .clickable { isLocallyRevealed = !isLocallyRevealed }
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(4.dp))

            // 4-slot display: Anti-video masked dots by default, or monospace Base32 when revealed
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center,
                verticalAlignment = Alignment.CenterVertically
            ) {
                for (pos in 0 until 4) {
                    val char = value.getOrNull(pos)
                    val text = when {
                        char == null -> "—"
                        showPlaintext -> char.toString()
                        else -> "•"
                    }
                    val textColor = when {
                        char == null -> Color.Gray.copy(alpha = 0.45f)
                        showPlaintext -> MaterialTheme.colorScheme.onSurface
                        else -> MaterialTheme.colorScheme.primary
                    }

                    Text(
                        text = text,
                        fontFamily = FontFamily.Monospace,
                        fontSize = if (showPlaintext || char == null) 14.sp else 18.sp,
                        fontWeight = FontWeight.Bold,
                        color = textColor,
                        modifier = Modifier.padding(horizontal = 2.dp)
                    )
                }
            }
        }
    }
}

@Composable
fun CardSlipsScreen(
    card: VaultCard?,
    sealedCardFp: String?,
    onRegenerate: () -> Unit,
    onBurnCard: () -> Unit,
    onRestoreCardToRam: () -> Unit,
    onPrintCard: () -> Unit,
    onSealToCivilId: () -> Unit,
    onDeleteSealedCard: () -> Unit
) {
    if (card == null) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            // Hardware Bound Card Badge if present
            if (sealedCardFp != null) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF1E3A8A).copy(alpha = 0.22f)),
                    border = BorderStroke(1.5.dp, Color(0xFF3B82F6)),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Shield, contentDescription = null, tint = Color(0xFF60A5FA), modifier = Modifier.size(28.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Column {
                                Text("Civil ID Hardware Seal Active", fontWeight = FontWeight.Bold, color = Color(0xFF60A5FA), style = MaterialTheme.typography.titleMedium)
                                Text("Bound Card: $sealedCardFp", style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                            }
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            "This card's polynomial is encrypted with Argon2id bound to your physical Civil ID NFC chip UID and device hardware UUID.\n\n" +
                            "• Unlocking vaults requires zero typing — simply tap your physical Civil ID card.\n" +
                            "• Plaintext recovery card is NOT stored in RAM or storage.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.height(12.dp))
                        Button(
                            onClick = onRestoreCardToRam,
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2563EB)),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Default.Contactless, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Restore Paper Card to RAM (Tap Civil ID)", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedButton(
                            onClick = onDeleteSealedCard,
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)
                        ) {
                            Icon(Icons.Default.Delete, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Unbind / Delete Sealed Card", fontSize = 12.sp)
                        }
                    }
                }
                Spacer(modifier = Modifier.height(20.dp))
            }

            Icon(
                imageVector = Icons.Default.Shield,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(64.dp)
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                if (sealedCardFp != null) "Physical Card Hardware Bound" else "No Paper Card in Memory",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                if (sealedCardFp != null) "Protected by Civil ID NFC Chip" else "Paper is the Single Source of Truth",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.primary,
                fontWeight = FontWeight.SemiBold
            )
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                "Your recovery card is designed to live solely on physical paper slips or bound to your physical government Civil ID NFC chip.\n\n" +
                "• Unlocking vaults NEVER requires a card in memory (you enter 15 challenge cells or tap your Civil ID).\n" +
                "• To create vaults or print a new paper card, generate one below. After printing or sealing, burn it from RAM.",
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(24.dp))
            Button(
                onClick = onRegenerate,
                modifier = Modifier.fillMaxWidth(0.85f)
            ) {
                Icon(Icons.Default.Add, contentDescription = null)
                Spacer(modifier = Modifier.width(8.dp))
                Text("Generate Fresh Paper Card")
            }
        }
        return
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        ElevatedCard(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text("Active Paper Card", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                        Text("140 Cells • 10 Slips • 260-bit Secret", style = MaterialTheme.typography.bodyMedium, color = Color.Gray)
                    }
                    Surface(
                        color = MaterialTheme.colorScheme.errorContainer,
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text(
                            "In RAM",
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
                Text("Card Fingerprint: ${card.fingerprint}", fontFamily = FontFamily.Monospace)
                Text("Master Key Fingerprint: ${card.keyFingerprint}", fontFamily = FontFamily.Monospace)
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Security Actions: Print & Burn
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = onPrintCard,
                modifier = Modifier.weight(1f)
            ) {
                Icon(Icons.Default.Print, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Print / PDF", fontSize = 13.sp)
            }
            Button(
                onClick = onBurnCard,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error,
                    contentColor = MaterialTheme.colorScheme.onError
                ),
                modifier = Modifier.weight(1f)
            ) {
                Icon(Icons.Default.DeleteForever, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Burn from RAM", fontSize = 13.sp)
            }
        }

        // Civil ID NFC Sealing Action
        Spacer(modifier = Modifier.height(8.dp))
        Button(
            onClick = onSealToCivilId,
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(
                containerColor = Color(0xFF1E3A8A),
                contentColor = Color.White
            ),
            shape = RoundedCornerShape(10.dp)
        ) {
            Icon(Icons.Default.Contactless, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text("💳 Seal to Civil ID NFC & Device (Zero-Typing)")
        }

        Spacer(modifier = Modifier.height(12.dp))

        LazyColumn(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            items(10) { slipIndex ->
                val slipNum = slipIndex + 1
                SlipPreviewCard(slipNumber = slipNum, card = card)
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        OutlinedButton(
            onClick = onRegenerate,
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Default.Refresh, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text("Regenerate Different Card")
        }
    }
}

@Composable
fun SlipPreviewCard(slipNumber: Int, card: VaultCard) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text("SLIP $slipNumber", fontWeight = FontWeight.Bold)
                Text("card ${card.fingerprint}", fontSize = 11.sp, color = Color.Gray)
            }

            Spacer(modifier = Modifier.height(8.dp))

            for (row in 0..1) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    for (col in 0..6) {
                        val cellNum = row * 7 + col + 1
                        val code = card.cells[Pair(slipNumber, cellNum)] ?: "----"
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text("c$cellNum", fontSize = 9.sp, color = Color.Gray)
                            Text(
                                code,
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                    }
                }
                if (row == 0) Spacer(modifier = Modifier.height(4.dp))
            }
        }
    }
}

private fun getFileName(context: Context, uri: Uri): String? {
    var name: String? = null
    if (uri.scheme == "content") {
        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (idx != -1) name = cursor.getString(idx)
            }
        }
    }
    return name ?: uri.path?.substringAfterLast('/')
}
