package com.qvault.app.nfc

import android.app.Activity
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Bundle

/**
 * Reader-mode plumbing for government Civil ID smartcards (ISO 14443 Type A/B).
 *
 * This class only captures the tag. Everything cryptographic happens in
 * [CivilIdChipReader], which opens the chip with PACE or BAC and identifies it by its
 * Active Authentication key.
 *
 * An earlier version tried to identify the card by firing unauthenticated SELECT and
 * READ BINARY commands at it. That cannot work: an ICAO 9303 chip answers 6A82 to every
 * such read until secure messaging is established, so the sweep always failed and fell
 * back to hashing the ATQB parameters, which are identical for every card of the same
 * product. That produced the same "identity" for every holder, and it is gone.
 */
class CivilIdNfcManager(
    private val onTagCaptured: (tag: Tag) -> Unit,
    private val onError: (String) -> Unit = {}
) : NfcAdapter.ReaderCallback {

    var isEnabled: Boolean = false
        private set

    fun isNfcAvailable(activity: Activity): Boolean {
        return NfcAdapter.getDefaultAdapter(activity) != null
    }

    fun isNfcEnabled(activity: Activity): Boolean {
        val adapter = NfcAdapter.getDefaultAdapter(activity)
        return adapter != null && adapter.isEnabled
    }

    fun enable(activity: Activity) {
        val adapter = NfcAdapter.getDefaultAdapter(activity)
        if (adapter == null) {
            onError("NFC is not supported on this hardware")
            return
        }
        if (!adapter.isEnabled) {
            onError("NFC is disabled in Android settings")
            return
        }

        // Capture Type A and Type B contactless government smartcards.
        val flags = NfcAdapter.FLAG_READER_NFC_A or
            NfcAdapter.FLAG_READER_NFC_B or
            NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK

        val options = Bundle().apply {
            putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 5000)
        }

        try {
            adapter.enableReaderMode(activity, this, flags, options)
            isEnabled = true
        } catch (e: Exception) {
            onError("Failed to enable NFC reader: ${e.message}")
        }
    }

    fun disable(activity: Activity) {
        if (!isEnabled) return
        val adapter = NfcAdapter.getDefaultAdapter(activity)
        try {
            adapter?.disableReaderMode(activity)
        } catch (_: Exception) {
        }
        isEnabled = false
    }

    override fun onTagDiscovered(tag: Tag?) {
        if (tag == null) return

        val techList = tag.techList.map { it.substringAfterLast(".") }
        if (!techList.contains("IsoDep")) {
            android.util.Log.w("QVault", "Tag without IsoDep: $techList")
            onError("This card has no readable smartcard chip. Use a government Civil ID.")
            return
        }

        android.util.Log.i("QVault", "Civil ID tag captured (Tech: $techList)")
        onTagCaptured(tag)
    }
}
