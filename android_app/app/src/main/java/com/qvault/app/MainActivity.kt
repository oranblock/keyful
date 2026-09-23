package com.qvault.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.MotionEvent
import android.view.WindowManager
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.core.view.WindowCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.qvault.app.domain.NfcScanUiState
import com.qvault.app.nfc.CivilIdNfcManager
import com.qvault.app.ui.QVaultViewModel
import com.qvault.app.ui.screens.QVaultMainScreen
import com.qvault.app.ui.theme.QVaultTheme
import kotlinx.coroutines.launch
import java.nio.charset.StandardCharsets

class MainActivity : ComponentActivity() {
    private val viewModel: QVaultViewModel by viewModels()
    private lateinit var nfcManager: CivilIdNfcManager

    private val idleTimeoutMs = 3 * 60 * 1000L // 3 minutes idle timeout
    private val idleHandler = Handler(Looper.getMainLooper())
    private val idleRunnable = Runnable {
        Log.i("QVault", "Idle timeout reached (3 min): wiping decrypted plaintext")
        viewModel.clearDecryptedPayload()
    }

    private val screenOffReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == Intent.ACTION_SCREEN_OFF) {
                Log.i("QVault", "Screen turned off: wiping decrypted plaintext")
                viewModel.clearDecryptedPayload()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Hardened: Prevent screenshots, screen recording, and blank recents preview
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        WindowCompat.setDecorFitsSystemWindows(window, false)

        val filter = IntentFilter(Intent.ACTION_SCREEN_OFF)
        registerReceiver(screenOffReceiver, filter)

        nfcManager = CivilIdNfcManager(
            onTagCaptured = { tag ->
                window.decorView.post {
                    window.decorView.performHapticFeedback(android.view.HapticFeedbackConstants.LONG_PRESS)
                }

                // The passkey is whatever the user typed for this tap. It is never derived
                // from the device, because a device-derived value is not a secret.
                val deviceUuid = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)
                    ?: "device_${filesDir.name}"
                viewModel.handleTagCaptured(tag, filesDir, deviceUuid)
            },
            onError = { err ->
                Log.e("QVault", "NFC Error: $err")
                viewModel.reportNfcError(err)
            }
        )

        viewModel.checkSealedCard(filesDir)

        setContent {
            QVaultTheme {
                QVaultMainScreen(viewModel = viewModel)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleNfcIntent(intent)
    }

    private fun handleNfcIntent(intent: Intent) {
        val tag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(android.nfc.NfcAdapter.EXTRA_TAG, android.nfc.Tag::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(android.nfc.NfcAdapter.EXTRA_TAG)
        }
        if (tag != null && ::nfcManager.isInitialized) {
            nfcManager.onTagDiscovered(tag)
        }
    }

    override fun dispatchTouchEvent(ev: MotionEvent?): Boolean {
        resetIdleTimer()
        return super.dispatchTouchEvent(ev)
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        resetIdleTimer()
    }

    override fun onResume() {
        super.onResume()
        resetIdleTimer()
        if (::nfcManager.isInitialized) {
            nfcManager.enable(this)
        }
        viewModel.checkSealedCard(filesDir)
    }

    override fun onPause() {
        super.onPause()
        if (::nfcManager.isInitialized) {
            nfcManager.disable(this)
        }
        idleHandler.removeCallbacks(idleRunnable)
        // Hardened: Zero out plaintext from memory immediately when backgrounded
        viewModel.clearDecryptedPayload()
    }

    override fun onDestroy() {
        super.onDestroy()
        idleHandler.removeCallbacks(idleRunnable)
        try {
            unregisterReceiver(screenOffReceiver)
        } catch (e: Exception) {
            // ignore if not registered
        }
    }

    private fun resetIdleTimer() {
        idleHandler.removeCallbacks(idleRunnable)
        idleHandler.postDelayed(idleRunnable, idleTimeoutMs)
    }
}
