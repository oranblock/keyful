package com.qvault.app.ui.print

import android.content.Context
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import android.os.Bundle
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.print.PageRange
import android.print.PrintAttributes
import android.print.PrintDocumentAdapter
import android.print.PrintDocumentInfo
import android.print.PrintManager
import com.qvault.app.domain.VaultCard
import java.io.FileOutputStream
import java.io.IOException

/**
 * Direct-stream PrintDocumentAdapter for physical QVault paper recovery cards.
 *
 * Security Guarantee: Zero disk leakage.
 * Renders vector graphics and typography directly into the print spooler pipe
 * via [destination.fileDescriptor]. No temporary PDF file is ever created on disk.
 */
class CardPrintDocumentAdapter(
    private val context: Context,
    private val card: VaultCard
) : PrintDocumentAdapter() {

    override fun onLayout(
        oldAttributes: PrintAttributes?,
        newAttributes: PrintAttributes,
        cancellationSignal: CancellationSignal?,
        callback: LayoutResultCallback,
        extras: Bundle?
    ) {
        if (cancellationSignal?.isCanceled == true) {
            callback.onLayoutCancelled()
            return
        }

        val info = PrintDocumentInfo.Builder("qvault_card_${card.fingerprint}.pdf")
            .setContentType(PrintDocumentInfo.CONTENT_TYPE_DOCUMENT)
            .setPageCount(1)
            .build()

        callback.onLayoutFinished(info, true)
    }

    override fun onWrite(
        pages: Array<out PageRange>?,
        destination: ParcelFileDescriptor,
        cancellationSignal: CancellationSignal?,
        callback: WriteResultCallback
    ) {
        val doc = PdfDocument()

        // Standard A4 dimensions: 595 x 842 points (72 dpi)
        val pageInfo = PdfDocument.PageInfo.Builder(595, 842, 1).create()
        val page = doc.startPage(pageInfo)

        if (cancellationSignal?.isCanceled == true) {
            callback.onWriteCancelled()
            doc.close()
            return
        }

        val canvas = page.canvas
        drawCardOnCanvas(canvas, pageInfo.pageWidth, pageInfo.pageHeight)

        doc.finishPage(page)

        try {
            // Write directly to print spooler stream pipe - zero disk persistence
            FileOutputStream(destination.fileDescriptor).use { out ->
                doc.writeTo(out)
            }
            callback.onWriteFinished(arrayOf(PageRange.ALL_PAGES))
        } catch (e: IOException) {
            callback.onWriteFailed(e.message)
        } finally {
            doc.close()
        }
    }

    private fun drawCardOnCanvas(canvas: android.graphics.Canvas, width: Int, height: Int) {
        val titlePaint = Paint().apply {
            isAntiAlias = true
            color = Color.BLACK
            textSize = 15f
            typeface = Typeface.create(Typeface.SANS_SERIF, Typeface.BOLD)
        }

        val subPaint = Paint().apply {
            isAntiAlias = true
            color = Color.DKGRAY
            textSize = 8.5f
            typeface = Typeface.create(Typeface.SANS_SERIF, Typeface.NORMAL)
        }

        val monoBold = Paint().apply {
            isAntiAlias = true
            color = Color.BLACK
            textSize = 9.5f
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
        }

        val monoSmall = Paint().apply {
            isAntiAlias = true
            color = Color.GRAY
            textSize = 7f
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL)
        }

        val borderPaint = Paint().apply {
            isAntiAlias = true
            color = Color.rgb(180, 180, 180)
            style = Paint.Style.STROKE
            strokeWidth = 0.8f
        }

        val linePaint = Paint().apply {
            isAntiAlias = true
            color = Color.rgb(215, 215, 215)
            style = Paint.Style.STROKE
            strokeWidth = 0.5f
        }

        val marginX = 36f
        val slipWidth = width - 2 * marginX

        // Header section
        canvas.drawText("QVAULT 5 — PAPER RECOVERY CARD", marginX, 42f, titlePaint)
        canvas.drawText(
            "Card Fingerprint: ${card.fingerprint}   |   Master Key Fingerprint: ${card.keyFingerprint}",
            marginX,
            57f,
            subPaint
        )
        canvas.drawText(
            "Scheme: Any 13 cells reconstruct the degree-12 polynomial in GF(2^20). Check cells detect typos.",
            marginX,
            69f,
            subPaint
        )

        // Draw 10 slips: stacked vertically with clean borders
        val startY = 82f
        val slipHeight = 67.5f
        val slipGap = 6.5f

        for (s in 1..10) {
            val yTop = startY + (s - 1) * (slipHeight + slipGap)
            val yBottom = yTop + slipHeight

            // Outer slip box
            canvas.drawRect(marginX, yTop, marginX + slipWidth, yBottom, borderPaint)

            // Slip header
            val slipHeaderPaint = Paint().apply {
                isAntiAlias = true
                color = Color.BLACK
                textSize = 9f
                typeface = Typeface.create(Typeface.SANS_SERIF, Typeface.BOLD)
            }
            canvas.drawText("SLIP $s", marginX + 8f, yTop + 12f, slipHeaderPaint)
            canvas.drawText("card ${card.fingerprint}", marginX + slipWidth - 65f, yTop + 12f, monoSmall)

            // Horizontal divider below slip header
            canvas.drawLine(marginX, yTop + 16f, marginX + slipWidth, yTop + 16f, linePaint)

            // 14 cells per slip: 2 rows of 7 columns
            val cellColWidth = slipWidth / 7f
            for (row in 0..1) {
                val rowY = yTop + 20f + row * 23f
                for (col in 0..6) {
                    val c = row * 7 + col + 1
                    val cellX = marginX + col * cellColWidth
                    val code = card.cells[Pair(s, c)] ?: "----"

                    canvas.drawText("c$c", cellX + 5f, rowY + 9f, monoSmall)
                    canvas.drawText(code, cellX + 5f, rowY + 20f, monoBold)

                    if (col > 0) {
                        canvas.drawLine(cellX, yTop + 16f, cellX, yBottom, linePaint)
                    }
                }
                if (row == 0) {
                    canvas.drawLine(marginX, yTop + 39f, marginX + slipWidth, yTop + 39f, linePaint)
                }
            }
        }
    }

    companion object {
        fun printCard(context: Context, card: VaultCard) {
            val printManager = context.getSystemService(Context.PRINT_SERVICE) as? PrintManager
            printManager?.print(
                "QVault_Card_${card.fingerprint}",
                CardPrintDocumentAdapter(context, card),
                null
            )
        }
    }
}
