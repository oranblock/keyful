package com.keyful.app.voicelab

import android.annotation.SuppressLint
import android.content.Context
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.os.Handler
import android.os.Looper
import org.json.JSONArray
import org.json.JSONObject
import org.vosk.Model
import org.vosk.Recognizer
import org.vosk.SpeakerModel
import org.vosk.android.StorageService
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import kotlin.math.sqrt

/**
 * Offline voice check (Vosk). Two independent tests:
 *  1. WHAT was said — decoy grammar (challenge words + near-miss + moan decoys).
 *     Bench: 96/96 real words, 0 junk / 0 near-miss fakes at conf >= 0.85.
 *  2. WHO said it — x-vector voiceprint (vosk-model-spk-0.4) of the whole answer,
 *     fed into VoiceLock as key material. Nothing voice-related is stored here.
 */
object VoskAsr {

    const val SR = 16000
    const val RECORD_MS = 1600
    const val MIN_CONF = 0.85f

    private var model: Model? = null
    private var spk: SpeakerModel? = null

    val ALL_WORDS = listOf(
        "river", "table", "seven", "orange", "purple", "guitar", "window", "planet",
        "silver", "tiger", "coffee", "garden", "rocket", "yellow", "market", "pencil",
        "castle", "dragon", "mountain", "engine", "banana", "candle", "flower", "island"
    )
    private val NEAR = listOf(
        "liver", "cable", "heaven", "porridge", "turtle", "sitar", "widow", "plant",
        "sliver", "tighter", "toffee", "pardon", "pocket", "hello", "basket", "stencil",
        "hassle", "wagon", "fountain", "ending", "bandana", "handle", "shower", "highland"
    )
    private val FILLERS = listOf(
        "oh", "ah", "mmm", "uh", "hmm", "her", "air", "the", "who",
        "them", "so", "and", "a", "i", "hey", "yeah", "no", "yes"
    )
    private val GRAMMAR: String = JSONArray().apply {
        (ALL_WORDS + NEAR + FILLERS).distinct().forEach { put(it) }
        put("[unk]")
    }.toString()

    class Heard(val text: String, val conf: Float, val pcm: ShortArray)

    val ready: Boolean get() = model != null && spk != null

    /** Unpack + load both models once. Callback on the main thread. */
    fun ensureModels(context: Context, onDone: (ok: Boolean, err: String?) -> Unit) {
        if (ready) { onDone(true, null); return }
        val main = Handler(Looper.getMainLooper())
        StorageService.unpack(context, "model", "model", { m ->
            model = m
            Thread {
                try {
                    val path = StorageService.sync(context, "spk", "spk")
                    spk = SpeakerModel(path)
                    main.post { onDone(true, null) }
                } catch (e: Exception) {
                    main.post { onDone(false, "speaker model: ${e.message}") }
                }
            }.start()
        }, { e -> onDone(false, e.message) })
    }

    @SuppressLint("MissingPermission")
    private fun capture(): ShortArray {
        val minBuf = AudioRecord.getMinBufferSize(SR, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
        val ar = AudioRecord(
            MediaRecorder.AudioSource.VOICE_RECOGNITION, SR, AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT, maxOf(minBuf, SR)
        )
        val total = SR * RECORD_MS / 1000
        val out = ShortArray(total)
        ar.startRecording()
        var read = 0
        while (read < total) {
            val n = ar.read(out, read, total - read)
            if (n <= 0) break
            read += n
        }
        ar.stop(); ar.release()
        return if (read == total) out else out.copyOf(read)
    }

    /** Record one word; return recognized text, lowest word confidence, and the audio. */
    fun transcribe(): Heard {
        val m = model ?: return Heard("", 0f, ShortArray(0))
        val pcm = capture()
        val rec = Recognizer(m, SR.toFloat(), GRAMMAR)
        rec.setWords(true)
        rec.acceptWaveForm(pcm, pcm.size)
        val json = JSONObject(rec.finalResult)
        rec.close()
        val text = json.optString("text", "").trim()
        val words = json.optJSONArray("result")
        var conf = 0f
        if (words != null && words.length() > 0) {
            conf = 1f
            for (k in 0 until words.length()) {
                conf = minOf(conf, words.getJSONObject(k).optDouble("conf", 0.0).toFloat())
            }
        }
        return Heard(text, conf, pcm)
    }

    /** Unit-length x-vector for the given speech, or null if too little speech. */
    fun voiceprint(pcm: ShortArray): FloatArray? {
        val m = model ?: return null
        val s = spk ?: return null
        val rec = Recognizer(m, SR.toFloat(), s)
        rec.acceptWaveForm(pcm, pcm.size)
        val arr = JSONObject(rec.finalResult).optJSONArray("spk")
        rec.close()
        if (arr == null || arr.length() == 0) return null
        val v = FloatArray(arr.length()) { arr.getDouble(it).toFloat() }
        var n = 0.0; for (x in v) n += x * x
        val norm = sqrt(n).toFloat()
        if (norm < 1e-6f) return null
        for (i in v.indices) v[i] /= norm
        return v
    }

    fun concat(parts: List<ShortArray>): ShortArray {
        val out = ShortArray(parts.sumOf { it.size }); var o = 0
        for (p in parts) { p.copyInto(out, o); o += p.size }
        return out
    }

    private fun vpFile(ctx: Context) = File(ctx.filesDir, "voiceprint.bin")

    /** Old builds stored a raw voiceprint; VoiceLock never does. Remove any leftover. */
    fun deleteVoiceprint(ctx: Context) { vpFile(ctx).delete() }
}
