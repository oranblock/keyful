package com.keyful.app.voicelab

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.SecureRandom

private enum class Step { LOADING, WORDS, PASS, WORKING, FAILED }

private const val SEAL_WORDS = 6
private const val OPEN_WORDS = 5
private const val MAX_MISSES = 3
private const val MIN_PASS = 8
private val Ok = Color(0xFF2E9E6B)
private val Bad = Color(0xFFE5533D)

/**
 * Full-screen voice (+ passphrase) step for QV6/QV7 vaults.
 * Random words must each be recognized (decoy grammar; 3 misses = new words). The whole
 * answer becomes the voiceprint, which only goes into the vault's voice lock as key
 * material and is wiped after use. Leaving the app closes the panel.
 *
 * onSubmit runs the key derivation: true = sealed / opened (the panel closes with done),
 * false = the lock stayed shut (new words, try again).
 */
@Composable
fun VoicePassPanel(
    sealing: Boolean,
    withPass: Boolean,
    intro: String,
    onSubmit: suspend (voice: FloatArray, pass: CharArray) -> Boolean,
    onClose: (done: Boolean) -> Unit
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var granted by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(ctx, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED)
    }
    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted = it }

    var step by remember { mutableStateOf(Step.LOADING) }
    var words by remember { mutableStateOf(listOf<String>()) }
    var idx by remember { mutableStateOf(0) }
    var misses by remember { mutableStateOf(0) }
    val takes = remember { mutableListOf<ShortArray>() }
    var heard by remember { mutableStateOf<VoskAsr.Heard?>(null) }
    var voice by remember { mutableStateOf<FloatArray?>(null) }   // memory only, wiped after use
    var msg by remember { mutableStateOf("Loading voice models…") }
    var good by remember { mutableStateOf(true) }
    var busy by remember { mutableStateOf(false) }
    var pass1 by remember { mutableStateOf("") }
    var pass2 by remember { mutableStateOf("") }
    val closeWith by rememberUpdatedState(onClose)

    fun forgetVoice() { voice?.fill(0f); voice = null }

    fun close(done: Boolean) {
        forgetVoice(); takes.clear(); pass1 = ""; pass2 = ""
        closeWith(done)
    }

    fun challenge(note: String) {
        words = VoskAsr.ALL_WORDS.shuffled(SecureRandom()).take(if (sealing) SEAL_WORDS else OPEN_WORDS)
        idx = 0; misses = 0; takes.clear(); heard = null
        pass1 = ""; pass2 = ""; forgetVoice()
        step = Step.WORDS; msg = note; good = !note.startsWith("✗")
    }

    LaunchedEffect(Unit) {
        VoskAsr.ensureModels(ctx) { ok, err ->
            if (!ok) { step = Step.FAILED; msg = "✗ Voice model error: $err"; good = false; return@ensureModels }
            challenge(if (sealing) "Read each word aloud" else "Say each word")
        }
    }

    val owner = LocalLifecycleOwner.current
    DisposableEffect(owner) {
        val obs = LifecycleEventObserver { _, e -> if (e == Lifecycle.Event.ON_STOP) close(false) }
        owner.lifecycle.addObserver(obs)
        onDispose { owner.lifecycle.removeObserver(obs); forgetVoice() }
    }

    BackHandler(enabled = !busy) { close(false) }

    fun submit(pass: CharArray) {
        val v = voice ?: return
        step = Step.WORKING; busy = true; good = true
        msg = if (sealing) "Sealing — deriving keys…" else "Opening — deriving keys…"
        scope.launch {
            var err: String? = null
            val ok = try {
                onSubmit(v, pass)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                err = e.message ?: e.javaClass.simpleName; false
            } finally {
                pass.fill('\u0000'); forgetVoice()
            }
            busy = false
            when {
                ok -> close(true)
                err != null -> { step = Step.FAILED; good = false; msg = "✗ $err" }
                sealing -> { step = Step.FAILED; good = false; msg = "✗ Could not seal: the card is no longer in memory" }
                else -> challenge("✗ Lock stayed shut — voice${if (withPass) " or passphrase" else ""} didn't fit. New words.")
            }
        }
    }

    fun say() {
        if (!granted) { ask.launch(Manifest.permission.RECORD_AUDIO); return }
        busy = true; msg = "listening…"; good = true
        scope.launch {
            val h = withContext(Dispatchers.Default) { VoskAsr.transcribe() }
            heard = h
            val target = words[idx]
            if (!(h.text == target && h.conf >= VoskAsr.MIN_CONF)) {
                misses++
                msg = when {
                    h.text.isBlank() -> "heard nothing"
                    h.text != target -> "heard \"${h.text}\" — not \"$target\""
                    else -> "only ${(h.conf * 100).toInt()}% sure — say it clearer"
                } + "   ($misses/$MAX_MISSES)"
                good = false
                if (misses >= MAX_MISSES) challenge("✗ $MAX_MISSES misses — new words")
                busy = false
                return@launch
            }
            takes.add(h.pcm); misses = 0
            if (idx + 1 < words.size) { idx++; msg = "✓ next word"; good = true; busy = false; return@launch }
            msg = "reading your voice…"
            val vp = withContext(Dispatchers.Default) { VoskAsr.voiceprint(VoskAsr.concat(takes)) }
            takes.clear()
            busy = false
            if (vp == null) { challenge("✗ Not enough speech — new words"); return@launch }
            voice = vp
            if (!withPass) { submit(CharArray(0)); return@launch }
            step = Step.PASS; good = true
            msg = if (sealing) "Voice captured. Choose a passphrase." else "Voice captured. Enter your passphrase."
        }
    }

    fun submitPass() {
        if (sealing) {
            if (pass1.length < MIN_PASS) { msg = "Passphrase: at least $MIN_PASS characters"; good = false; return }
            if (pass1 != pass2) { msg = "Passphrases don't match"; good = false; return }
        }
        val pass = pass1.toCharArray()
        pass1 = ""; pass2 = ""
        submit(pass)
    }

    val scheme = MaterialTheme.colorScheme
    Surface(Modifier.fillMaxSize(), color = scheme.background) {
        Column(
            Modifier.fillMaxSize().systemBarsPadding().imePadding()
                .verticalScroll(rememberScrollState()).padding(horizontal = 24.dp, vertical = 12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (sealing) "🎙 Seal with your voice" else "🎙 Open with your voice",
                    fontWeight = FontWeight.Bold, fontSize = 20.sp, modifier = Modifier.weight(1f)
                )
                IconButton(onClick = { close(false) }, enabled = !busy) { Icon(Icons.Default.Close, contentDescription = "Close") }
            }
            Text(intro, color = scheme.onSurfaceVariant, fontSize = 13.sp, textAlign = TextAlign.Center)

            if (!granted) Button(onClick = { ask.launch(Manifest.permission.RECORD_AUDIO) }) { Text("Grant microphone") }

            when (step) {
                Step.LOADING, Step.WORKING -> {
                    Spacer(Modifier.height(60.dp))
                    CircularProgressIndicator()
                    Text(msg, textAlign = TextAlign.Center)
                }

                Step.WORDS -> {
                    Text("word ${idx + 1}/${words.size}  ·  misses $misses/$MAX_MISSES", color = scheme.onSurfaceVariant, fontSize = 14.sp)
                    Spacer(Modifier.height(12.dp))
                    Text(words.getOrElse(idx) { "" }, fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold, fontSize = 56.sp, textAlign = TextAlign.Center)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        repeat(words.size) { k ->
                            Box(Modifier.size(14.dp).background(
                                if (k < idx) Ok else if (k == idx) scheme.primary else scheme.surfaceVariant, CircleShape))
                        }
                    }
                    heard?.let { h ->
                        Text("heard: ${if (h.text.isBlank()) "(nothing)" else h.text}  ·  ${(h.conf * 100).toInt()}% sure",
                            color = scheme.onSurfaceVariant, fontFamily = FontFamily.Monospace, fontSize = 14.sp)
                    }
                    Text(msg, color = if (good) Ok else Bad, fontWeight = FontWeight.Bold, fontSize = 16.sp, textAlign = TextAlign.Center)
                    Spacer(Modifier.height(12.dp))
                    Button(onClick = { say() }, enabled = granted && !busy, modifier = Modifier.fillMaxWidth().height(64.dp)) {
                        Text(if (busy) "listening…" else "Say the word", fontSize = 20.sp, fontWeight = FontWeight.Bold)
                    }
                }

                Step.PASS -> {
                    Text(msg, color = if (good) scheme.primary else Bad, fontSize = 15.sp, textAlign = TextAlign.Center)
                    OutlinedTextField(pass1, { pass1 = it },
                        label = { Text(if (sealing) "Passphrase (min $MIN_PASS)" else "Passphrase") },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password), singleLine = true,
                        modifier = Modifier.fillMaxWidth())
                    if (sealing) {
                        OutlinedTextField(pass2, { pass2 = it }, label = { Text("Repeat passphrase") },
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password), singleLine = true,
                            modifier = Modifier.fillMaxWidth())
                        Text("No reset exists: forget it and this vault stays shut.",
                            color = Bad, fontSize = 12.sp, textAlign = TextAlign.Center)
                    }
                    Button(onClick = { submitPass() }, enabled = pass1.isNotEmpty(), modifier = Modifier.fillMaxWidth().height(60.dp)) {
                        Text(if (sealing) "Seal vault" else "Open vault", fontWeight = FontWeight.Bold)
                    }
                }

                Step.FAILED -> {
                    Spacer(Modifier.height(40.dp))
                    Text(msg, color = Bad, fontWeight = FontWeight.Bold, fontSize = 18.sp, textAlign = TextAlign.Center)
                    OutlinedButton(onClick = { close(false) }, modifier = Modifier.fillMaxWidth()) { Text("Close") }
                }
            }
        }
    }
}
