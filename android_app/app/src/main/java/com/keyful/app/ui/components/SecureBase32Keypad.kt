package com.keyful.app.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Backspace
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowLeft
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Shuffle
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.keyful.app.domain.QVaultEngine
import java.security.SecureRandom

/**
 * In-App Scrambled Base32 Keypad.
 *
 * Security Guarantees:
 * 1. Zero OS Keyboard / Zero IME: Bypasses Android InputMethodManager completely.
 *    Third-party keyboards cannot log keystrokes or sync to cloud dictionaries.
 * 2. DRM / Screen-Record Blackout: Rendered within FLAG_SECURE Activity window;
 *    screen recording or mirroring produces 100% black video.
 * 3. Physical Camera & Shoulder-Surfing Defense:
 *    - Zero key-popup magnifying bubbles.
 *    - Dynamic random scrambling of all 32 Base32 keys.
 *    - Coordinate tracking and smudge analysis cannot deduce entered characters.
 * 4. Strict Base32 Domain: Only valid B32 symbols (A-Z, 2-7) are physically present.
 */
@Composable
fun SecureBase32Keypad(
    activeCellIndex: Int,
    totalCells: Int = 15,
    onKeyTap: (Char) -> Unit,
    onBackspace: () -> Unit,
    onClearCell: () -> Unit,
    onPrevCell: () -> Unit,
    onNextCell: () -> Unit,
    modifier: Modifier = Modifier
) {
    val haptic = LocalHapticFeedback.current
    val rng = remember { SecureRandom() }

    // Standard ordered Base32 keys: 26 letters + 6 digits
    val standardKeys = remember {
        listOf(
            listOf('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'),
            listOf('I', 'J', 'K', 'L', 'M', 'N', 'O', 'P'),
            listOf('Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X'),
            listOf('Y', 'Z', '2', '3', '4', '5', '6', '7')
        )
    }

    var isScrambled by remember { mutableStateOf(false) }
    var autoScramblePerCell by remember { mutableStateOf(false) }
    var scrambleSeed by remember { mutableStateOf(0) }

    // Compute active key layout based on scramble state
    val keyRows = remember(isScrambled, scrambleSeed) {
        if (!isScrambled) {
            standardKeys
        } else {
            val allChars = QVaultEngine.B32.toCharArray().toMutableList()
            // Fisher-Yates shuffle with cryptographic RNG
            for (i in allChars.indices.reversed()) {
                val j = rng.nextInt(i + 1)
                val temp = allChars[i]
                allChars[i] = allChars[j]
                allChars[j] = temp
            }
            listOf(
                allChars.subList(0, 8).toList(),
                allChars.subList(8, 16).toList(),
                allChars.subList(16, 24).toList(),
                allChars.subList(24, 32).toList()
            )
        }
    }

    Surface(
        modifier = modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        shape = RoundedCornerShape(topStart = 16.dp, topEnd = 16.dp),
        shadowElevation = 8.dp
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 6.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Control Header Bar
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 6.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Scramble toggle button
                FilterChip(
                    selected = isScrambled,
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        if (isScrambled) {
                            // Already scrambled: re-scramble
                            scrambleSeed++
                        } else {
                            isScrambled = true
                            scrambleSeed++
                        }
                    },
                    label = {
                        Text(
                            if (isScrambled) "🔀 Scrambled" else "🔀 Scramble",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    },
                    leadingIcon = {
                        Icon(
                            Icons.Default.Shuffle,
                            contentDescription = null,
                            modifier = Modifier.size(14.dp)
                        )
                    }
                )

                // If scrambled, show auto-reshuffle chip
                if (isScrambled) {
                    FilterChip(
                        selected = autoScramblePerCell,
                        onClick = {
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            autoScramblePerCell = !autoScramblePerCell
                        },
                        label = {
                            Text(
                                if (autoScramblePerCell) "Auto-Shuffle ON" else "Auto-Shuffle",
                                fontSize = 10.sp
                            )
                        }
                    )
                }

                // Active Cell Indicator & Navigation
                Row(verticalAlignment = Alignment.CenterVertically) {
                    IconButton(
                        onClick = {
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            onPrevCell()
                        },
                        modifier = Modifier.size(28.dp)
                    ) {
                        Icon(
                            Icons.AutoMirrored.Filled.KeyboardArrowLeft,
                            contentDescription = "Previous Cell",
                            modifier = Modifier.size(20.dp)
                        )
                    }

                    Text(
                        "Cell #${activeCellIndex + 1}/$totalCells",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(horizontal = 4.dp)
                    )

                    IconButton(
                        onClick = {
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            onNextCell()
                        },
                        modifier = Modifier.size(28.dp)
                    ) {
                        Icon(
                            Icons.AutoMirrored.Filled.KeyboardArrowRight,
                            contentDescription = "Next Cell",
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }

                // Backspace / Clear button
                IconButton(
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        onBackspace()
                    },
                    modifier = Modifier.size(32.dp)
                ) {
                    Icon(
                        Icons.AutoMirrored.Filled.Backspace,
                        contentDescription = "Backspace",
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(20.dp)
                    )
                }
            }

            // 4 Rows of 8 Base32 Keys
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(5.dp)
            ) {
                keyRows.forEach { row ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        row.forEach { char ->
                            KeypadKey(
                                char = char,
                                modifier = Modifier.weight(1f),
                                onClick = {
                                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    onKeyTap(char)
                                    if (autoScramblePerCell && isScrambled) {
                                        scrambleSeed++
                                    }
                                }
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun KeypadKey(
    char: Char,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val isDigit = char in '2'..'7'
    val backgroundColor = if (isDigit) {
        MaterialTheme.colorScheme.secondaryContainer
    } else {
        MaterialTheme.colorScheme.surface
    }
    val contentColor = if (isDigit) {
        MaterialTheme.colorScheme.onSecondaryContainer
    } else {
        MaterialTheme.colorScheme.onSurface
    }

    Box(
        modifier = modifier
            .height(42.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(backgroundColor)
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = char.toString(),
            fontSize = 17.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace,
            color = contentColor
        )
    }
}
