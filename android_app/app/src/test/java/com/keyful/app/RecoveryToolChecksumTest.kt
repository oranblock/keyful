package com.keyful.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * The README publishes the SHA-256 of qvault5.py so users can spot a tampered copy before
 * typing their cells into it. This fails whenever the script changes and the README does not.
 */
class RecoveryToolChecksumTest {

    @Test fun readmeChecksumMatchesQvault5py() {
        val root = generateSequence(File("").absoluteFile) { it.parentFile }
            .first { File(it, "qvault5.py").exists() }
        val digest = MessageDigest.getInstance("SHA-256").digest(File(root, "qvault5.py").readBytes())
        val actual = digest.joinToString("") { "%02x".format(it) }
        val published = Regex("([0-9a-f]{64})  qvault5\\.py").find(File(root, "README.md").readText())
        assertNotNull("README has no qvault5.py checksum line", published)
        assertEquals(
            "README checksum is stale: put the output of `sha256sum qvault5.py` in the README",
            actual,
            published!!.groupValues[1]
        )
    }
}
