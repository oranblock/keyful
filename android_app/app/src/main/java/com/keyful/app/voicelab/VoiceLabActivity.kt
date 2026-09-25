package com.keyful.app.voicelab

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Voice + passphrase lock (experiment).
 * The voice is key material inside VoiceLock — the app never compares voices itself.
 * ENROLL (6 words) -> SETUP (passphrase + secret, sealed) -> LOCKED (5 random words,
 * each must be recognized) -> PASS (passphrase) -> VoiceLock.open: opens only if the
 * passphrase AND your voice bits are right. Relocks when the app leaves the screen.
 */
class VoiceLabActivity : ComponentActivity() {
    private val relock = mutableStateOf(0)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContent { MaterialTheme { VoiceLockScreen(relock) } }
    }
    override fun onStop() { super.onStop(); relock.value++ }
}

private const val ENROLL_WORDS = 6
private const val CHALLENGE_WORDS = 5
private const val MAX_MISSES = 3
private const val MIN_PASS = 8
private enum class Mode { LOADING, ENROLL, SETUP, LOCKED, PASS, UNLOCKED }

private val Bg = Color(0xFF0E1116); private val Dim = Color(0xFF9AA4B2)
private val Ok = Color(0xFF4CC38A); private val Bad = Color(0xFFF3826B); private val Accent = Color(0xFF7F9CFF)

@Composable
private fun VoiceLockScreen(relock: State<Int>) {
    val ctx = LocalContext.current
    val dir = ctx.filesDir
    val scope = rememberCoroutineScope()
    var granted by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(ctx, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED)
    }
    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted = it }

    var mode by remember { mutableStateOf(Mode.LOADING) }
    var words by remember { mutableStateOf(listOf<String>()) }
    var idx by remember { mutableStateOf(0) }
    var misses by remember { mutableStateOf(0) }
    val takes = remember { mutableListOf<ShortArray>() }
    var heard by remember { mutableStateOf<VoskAsr.Heard?>(null) }
    var voice by remember { mutableStateOf<FloatArray?>(null) }   // held in memory only
    var msg by remember { mutableStateOf("Loading voice models…") }
    var good by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var pass1 by remember { mutableStateOf("") }
    var pass2 by remember { mutableStateOf("") }
    var secretIn by remember { mutableStateOf("") }
    var opened by remember { mutableStateOf<String?>(null) }
    var openedLock by remember { mutableStateOf(-1) }

    fun forgetVoice() { voice?.fill(0f); voice = null }

    fun challenge(m: Mode, note: String) {
        words = VoskAsr.ALL_WORDS.shuffled().take(if (m == Mode.ENROLL) ENROLL_WORDS else CHALLENGE_WORDS)
        idx = 0; misses = 0; takes.clear(); heard = null; mode = m; msg = note; good = false
        pass1 = ""; pass2 = ""; opened = null; forgetVoice()
    }

    LaunchedEffect(Unit) {
        VoskAsr.ensureModels(ctx) { ok, err ->
            if (!ok) { msg = "model error: $err"; return@ensureModels }
            VoskAsr.deleteVoiceprint(ctx)   // older builds kept a raw voiceprint; never keep one
            if (VoiceLock.exists(dir)) challenge(Mode.LOCKED, "Locked. Say each word.")
            else challenge(Mode.ENROLL, "Enroll your voice: read each word aloud")
        }
    }
    LaunchedEffect(relock.value) {
        if (relock.value > 0 && (mode == Mode.UNLOCKED || mode == Mode.PASS))
            challenge(Mode.LOCKED, "Locked again. Say each word.")
    }

    fun say() {
        if (!granted) { ask.launch(Manifest.permission.RECORD_AUDIO); return }
        busy = true; msg = "listening…"
        scope.launch {
            val h = withContext(Dispatchers.Default) { VoskAsr.transcribe() }
            heard = h
            val target = words[idx]
            if (!(h.text == target && h.conf >= VoskAsr.MIN_CONF)) {
                misses++; good = false
                msg = (if (h.text.isBlank()) "heard nothing"
                       else if (h.text != target) "heard \"${h.text}\" — not \"$target\""
                       else "only ${(h.conf * 100).toInt()}% sure — say it clearer") + "   ($misses/$MAX_MISSES)"
                if (misses >= MAX_MISSES) challenge(mode, "✗ $MAX_MISSES misses — new words")
                busy = false; return@launch
            }
            takes.add(h.pcm); misses = 0; good = true
            if (idx + 1 < words.size) { idx++; msg = "✓ next word"; busy = false; return@launch }
            msg = "reading your voice…"
            val vp = withContext(Dispatchers.Default) { VoskAsr.voiceprint(VoskAsr.concat(takes)) }
            takes.clear()
            if (vp == null) { challenge(mode, "not enough speech — try again"); busy = false; return@launch }
            voice = vp
            if (mode == Mode.ENROLL) { mode = Mode.SETUP; msg = "Voice captured. Set a passphrase and your secret." }
            else { mode = Mode.PASS; msg = "Voice captured. Enter your passphrase." }
            busy = false
        }
    }

    fun seal() {
        val v = voice ?: return
        if (pass1.length < MIN_PASS) { msg = "passphrase: at least $MIN_PASS characters"; good = false; return }
        if (pass1 != pass2) { msg = "passphrases don't match"; good = false; return }
        if (secretIn.isBlank()) { msg = "type the secret to lock"; good = false; return }
        busy = true; msg = "sealing — deriving keys…"
        scope.launch {
            withContext(Dispatchers.Default) { VoiceLock.seal(dir, pass1.toCharArray(), v, secretIn.toByteArray()) }
            secretIn = ""
            challenge(Mode.LOCKED, "Sealed ✓ Locked with your voice + passphrase. Unlock: say each word.")
            busy = false
        }
    }

    fun open() {
        val v = voice ?: return
        busy = true; msg = "opening — deriving keys…"
        scope.launch {
            val o = withContext(Dispatchers.Default) { VoiceLock.open(dir, pass1.toCharArray(), v) }
            forgetVoice()
            if (o != null) {
                opened = String(o.secret); openedLock = o.lockIndex; o.secret.fill(0)
                mode = Mode.UNLOCKED; msg = "UNLOCKED"; good = true
            } else {
                challenge(Mode.LOCKED, "✗ lock stayed shut — passphrase or voice didn't fit. New words.")
            }
            busy = false
        }
    }

    Column(
        Modifier.fillMaxSize().background(Bg).verticalScroll(rememberScrollState()).padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        if (!granted) Button(onClick = { ask.launch(Manifest.permission.RECORD_AUDIO) }) { Text("Grant microphone") }
        Text(when (mode) {
            Mode.LOADING -> "loading"
            Mode.ENROLL -> "ENROLL VOICE · word ${idx + 1}/${words.size}"
            Mode.SETUP -> "SET PASSPHRASE + SECRET"
            Mode.LOCKED -> "🔒 LOCKED · word ${idx + 1}/${words.size} · misses $misses/$MAX_MISSES"
            Mode.PASS -> "🔒 PASSPHRASE"
            Mode.UNLOCKED -> "🔓 UNLOCKED"
        }, color = Dim, fontSize = 14.sp)

        when (mode) {
            Mode.LOADING -> { Spacer(Modifier.height(120.dp)); Text(msg, color = Color.White) }

            Mode.ENROLL, Mode.LOCKED -> {
                Spacer(Modifier.height(40.dp))
                Text(words.getOrElse(idx) { "" }, color = Color.White, fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold, fontSize = 60.sp, textAlign = TextAlign.Center)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    repeat(words.size) { k ->
                        Box(Modifier.size(14.dp).background(
                            if (k < idx) Ok else if (k == idx) Accent else Color(0xFF2A3340), CircleShape))
                    }
                }
                heard?.let { h ->
                    Text("heard: ${if (h.text.isBlank()) "(nothing)" else h.text}  ·  ${(h.conf * 100).toInt()}% sure",
                        color = Color(0xFFC9D2E0), fontFamily = FontFamily.Monospace, fontSize = 14.sp)
                }
                Text(msg, color = if (good) Ok else Bad, fontWeight = FontWeight.Bold, fontSize = 16.sp, textAlign = TextAlign.Center)
                Spacer(Modifier.height(24.dp))
                Button(onClick = { say() }, enabled = granted && !busy, modifier = Modifier.fillMaxWidth().height(66.dp)) {
                    Text(if (busy) "listening…" else "Say the word", fontSize = 20.sp, fontWeight = FontWeight.Bold)
                }
            }

            Mode.SETUP -> {
                Text(msg, color = Accent, fontSize = 15.sp, textAlign = TextAlign.Center)
                OutlinedTextField(pass1, { pass1 = it }, label = { Text("Passphrase (min $MIN_PASS)") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password), singleLine = true,
                    modifier = Modifier.fillMaxWidth())
                OutlinedTextField(pass2, { pass2 = it }, label = { Text("Repeat passphrase") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password), singleLine = true,
                    modifier = Modifier.fillMaxWidth())
                OutlinedTextField(secretIn, { secretIn = it }, label = { Text("Secret to lock") },
                    minLines = 3, modifier = Modifier.fillMaxWidth())
                Text("Opens only with this passphrase AND your voice. Your voice is not stored — only locks made from it.",
                    color = Dim, fontSize = 12.sp, textAlign = TextAlign.Center)
                Button(onClick = { seal() }, enabled = !busy, modifier = Modifier.fillMaxWidth().height(60.dp)) {
                    Text(if (busy) "sealing…" else "Seal with voice + passphrase", fontWeight = FontWeight.Bold)
                }
            }

            Mode.PASS -> {
                Text(msg, color = Accent, fontSize = 15.sp, textAlign = TextAlign.Center)
                OutlinedTextField(pass1, { pass1 = it }, label = { Text("Passphrase") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password), singleLine = true,
                    modifier = Modifier.fillMaxWidth())
                Button(onClick = { open() }, enabled = !busy && pass1.isNotEmpty(), modifier = Modifier.fillMaxWidth().height(60.dp)) {
                    Text(if (busy) "opening…" else "Open lock", fontWeight = FontWeight.Bold)
                }
            }

            Mode.UNLOCKED -> {
                Text("UNLOCKED", color = Ok, fontWeight = FontWeight.Bold, fontSize = 40.sp)
                Text("passphrase + your voice opened lock #${openedLock + 1} of ${VoiceLock.L}", color = Dim, fontSize = 13.sp)
                Surface(color = Color(0xFF161B23), shape = MaterialTheme.shapes.medium, modifier = Modifier.fillMaxWidth()) {
                    Text(opened ?: "", color = Color.White, fontFamily = FontFamily.Monospace, modifier = Modifier.padding(16.dp))
                }
                Button(onClick = { challenge(Mode.LOCKED, "Locked. Say each word.") }, modifier = Modifier.fillMaxWidth()) { Text("Lock now") }
                OutlinedButton(onClick = {
                    VoiceLock.wipe(dir); challenge(Mode.ENROLL, "Enroll your voice: read each word aloud")
                }, modifier = Modifier.fillMaxWidth()) { Text("Erase lock + re-enroll") }
            }
        }
    }
}
