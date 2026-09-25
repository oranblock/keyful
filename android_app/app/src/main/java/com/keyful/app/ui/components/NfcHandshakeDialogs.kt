package com.keyful.app.ui.components

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.window.Dialog
import com.keyful.app.domain.NfcScanUiState
import com.keyful.app.nfc.CivilIdChipReader

/**
 * Collects what is needed to open the passport chip and to key the vault.
 *
 * The chip will not talk to any reader that cannot prove it is holding the card, so the
 * card access number (or the document number with the two dates) is required by the
 * standard, not by us. The passkey is separate: it is what stops the card alone from
 * opening the vault.
 */
@Composable
fun CardCredentialsDialog(
    onConfirm: (accessKey: CivilIdChipReader.AccessKey, passkey: ByteArray) -> Unit,
    onCancel: () -> Unit
) {
    var useCan by remember { mutableStateOf(false) }   // passports print the details, rarely a CAN
    var can by remember { mutableStateOf("") }
    var documentNumber by remember { mutableStateOf("") }
    var dateOfBirth by remember { mutableStateOf("") }
    var dateOfExpiry by remember { mutableStateOf("") }
    var passkey by remember { mutableStateOf("") }

    val datesLookValid = dateOfBirth.length == 6 && dateOfExpiry.length == 6
    val accessReady = if (useCan) can.isNotBlank() else documentNumber.isNotBlank() && datesLookValid
    val canConfirm = accessReady && passkey.length >= 6

    Dialog(onDismissRequest = onCancel) {
        Card(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(modifier = Modifier.padding(24.dp)) {
                Text(
                    "Unlock your passport chip",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    "The chip only opens for a reader that knows what is printed on the passport's photo page.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Spacer(modifier = Modifier.height(16.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = !useCan,
                        onClick = { useCan = false },
                        label = { Text("Passport details") }
                    )
                    FilterChip(
                        selected = useCan,
                        onClick = { useCan = true },
                        label = { Text("Card number (CAN)") }
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))
                if (useCan) {
                    OutlinedTextField(
                        value = can,
                        onValueChange = { can = it.filter { ch -> ch.isDigit() } },
                        label = { Text("Card Access Number") },
                        supportingText = { Text("Only if your passport prints a card access number") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                } else {
                    OutlinedTextField(
                        value = documentNumber,
                        onValueChange = { documentNumber = it.uppercase() },
                        label = { Text("Passport number") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = dateOfBirth,
                        onValueChange = { dateOfBirth = it.filter { ch -> ch.isDigit() }.take(6) },
                        label = { Text("Date of birth") },
                        supportingText = { Text("YYMMDD, for example 850317") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = dateOfExpiry,
                        onValueChange = { dateOfExpiry = it.filter { ch -> ch.isDigit() }.take(6) },
                        label = { Text("Date of expiry") },
                        supportingText = { Text("YYMMDD, for example 310317") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))
                HorizontalDivider()
                Spacer(modifier = Modifier.height(16.dp))

                OutlinedTextField(
                    value = passkey,
                    onValueChange = { passkey = it },
                    label = { Text("Your passkey") },
                    supportingText = {
                        Text("At least 6 characters. Without this, anyone holding your passport could open the vault.")
                    },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(20.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(onClick = onCancel, modifier = Modifier.weight(1f)) {
                        Text("Cancel")
                    }
                    Button(
                        onClick = {
                            val accessKey = if (useCan) {
                                CivilIdChipReader.AccessKey.Can(can.trim())
                            } else {
                                CivilIdChipReader.AccessKey.Mrz(
                                    documentNumber.trim(),
                                    dateOfBirth.trim(),
                                    dateOfExpiry.trim()
                                )
                            }
                            onConfirm(accessKey, passkey.toByteArray(Charsets.UTF_8))
                        },
                        enabled = canConfirm,
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Scan card")
                    }
                }
            }
        }
    }
}

@Composable
fun NfcScanDialog(
    state: NfcScanUiState,
    onCancel: () -> Unit
) {
    if (state is NfcScanUiState.Idle) return

    Dialog(onDismissRequest = onCancel) {
        Card(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                when (state) {
                    is NfcScanUiState.WaitingForCard -> {
                        Icon(
                            imageVector = Icons.Default.Contactless,
                            contentDescription = "NFC",
                            modifier = Modifier.size(64.dp),
                            tint = MaterialTheme.colorScheme.primary
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            "Passport NFC Ready",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            state.message,
                            style = MaterialTheme.typography.bodyMedium,
                            textAlign = TextAlign.Center,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            "Hold card firmly against the back of your phone",
                            style = MaterialTheme.typography.labelMedium,
                            color = Color(0xFF2563EB),
                            fontWeight = FontWeight.SemiBold
                        )
                        Spacer(modifier = Modifier.height(20.dp))
                        OutlinedButton(onClick = onCancel) {
                            Text("Cancel")
                        }
                    }
                    is NfcScanUiState.Processing -> {
                        CircularProgressIndicator(modifier = Modifier.size(48.dp))
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            "Authenticating Chip",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            state.message,
                            style = MaterialTheme.typography.bodySmall,
                            textAlign = TextAlign.Center
                        )
                    }
                    is NfcScanUiState.Success -> {
                        Icon(
                            imageVector = Icons.Default.CheckCircle,
                            contentDescription = "Success",
                            modifier = Modifier.size(56.dp),
                            tint = Color(0xFF2E7D32)
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            "Success",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF2E7D32)
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            state.message,
                            style = MaterialTheme.typography.bodyMedium,
                            textAlign = TextAlign.Center
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Button(onClick = onCancel) {
                            Text("Done")
                        }
                    }
                    is NfcScanUiState.Error -> {
                        Icon(
                            imageVector = Icons.Default.ErrorOutline,
                            contentDescription = "Error",
                            modifier = Modifier.size(56.dp),
                            tint = MaterialTheme.colorScheme.error
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            "Authentication Failed",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.error
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            state.error,
                            style = MaterialTheme.typography.bodyMedium,
                            textAlign = TextAlign.Center
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Button(onClick = onCancel) {
                            Text("Dismiss")
                        }
                    }
                    else -> {}
                }
            }
        }
    }
}

@Composable
fun EphemeralChallengeDialog(
    challengeStr: String?,
    onDismiss: () -> Unit,
    onResolve: (String) -> Unit
) {
    if (challengeStr == null) return
    var responseInput by remember { mutableStateOf("") }

    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            shape = RoundedCornerShape(20.dp)
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    "Ephemeral Challenge QR",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    "Scan with Keyholder Phone (Phone B) • Expires in 60s",
                    style = MaterialTheme.typography.bodySmall,
                    color = Color.Gray
                )
                Spacer(modifier = Modifier.height(12.dp))

                // Vector QR view
                QrCodeView(
                    content = challengeStr,
                    modifier = Modifier.size(240.dp)
                )

                Spacer(modifier = Modifier.height(12.dp))
                OutlinedTextField(
                    value = responseInput,
                    onValueChange = { responseInput = it },
                    label = { Text("Paste Peer Response (QVR1:...)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace)
                )
                Spacer(modifier = Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(onClick = onDismiss, modifier = Modifier.weight(1f)) {
                        Text("Cancel")
                    }
                    Button(
                        onClick = { if (responseInput.isNotBlank()) onResolve(responseInput.trim()) },
                        modifier = Modifier.weight(1f),
                        enabled = responseInput.isNotBlank()
                    ) {
                        Text("Unseal Vault")
                    }
                }
            }
        }
    }
}

@Composable
fun GeneratedResponseQrDialog(
    responseStr: String?,
    onDismiss: () -> Unit
) {
    if (responseStr == null) return

    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            shape = RoundedCornerShape(20.dp)
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    "Ephemeral Response QR",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    "Show this to Vault Phone (Phone A) to scan",
                    style = MaterialTheme.typography.bodySmall,
                    color = Color(0xFF2E7D32),
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(modifier = Modifier.height(12.dp))

                QrCodeView(
                    content = responseStr,
                    modifier = Modifier.size(240.dp)
                )

                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    "Single-use encrypted ciphertext. Copying or photographing is harmless; replay will fail.",
                    style = MaterialTheme.typography.bodySmall,
                    color = Color.Gray,
                    textAlign = TextAlign.Center
                )
                Spacer(modifier = Modifier.height(16.dp))
                Button(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
                    Text("Done")
                }
            }
        }
    }
}

@Composable
fun SignPeerChallengeDialog(
    isOpen: Boolean,
    onDismiss: () -> Unit,
    onSign: (String) -> Unit
) {
    if (!isOpen) return
    var challengeInput by remember { mutableStateOf("") }

    Dialog(onDismissRequest = onDismiss) {
        Card(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            shape = RoundedCornerShape(20.dp)
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    "Sign Wireless Challenge",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    "Paste peer's QVC1:... challenge, then tap your passport",
                    style = MaterialTheme.typography.bodySmall,
                    color = Color.Gray
                )
                Spacer(modifier = Modifier.height(16.dp))
                OutlinedTextField(
                    value = challengeInput,
                    onValueChange = { challengeInput = it },
                    label = { Text("Peer Challenge (QVC1:...)") },
                    modifier = Modifier.fillMaxWidth(),
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace)
                )
                Spacer(modifier = Modifier.height(16.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(onClick = onDismiss, modifier = Modifier.weight(1f)) {
                        Text("Cancel")
                    }
                    Button(
                        onClick = {
                            if (challengeInput.isNotBlank()) {
                                onSign(challengeInput.trim())
                                onDismiss()
                            }
                        },
                        modifier = Modifier.weight(1f),
                        enabled = challengeInput.isNotBlank()
                    ) {
                        Text("Tap Passport")
                    }
                }
            }
        }
    }
}
