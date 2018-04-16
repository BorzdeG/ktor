package io.ktor.network.tls

import io.ktor.http.cio.internals.*
import kotlinx.coroutines.experimental.io.packet.*
import kotlinx.io.core.*
import kotlinx.io.core.ByteReadPacket
import java.io.*
import java.security.*

internal fun ByteReadPacket.duplicate(): Pair<ByteReadPacket, ByteReadPacket> {
    if (this.isEmpty) return ByteReadPacket.Empty to ByteReadPacket.Empty
    return this to copy()
}

class Digest(private val hashName: String) : Closeable {
    private val state = WritePacket()

    fun update(packet: ByteReadPacket) {
        state.writePacket(packet)
    }

    fun doHash(): ByteArray = state.preview { handshakes: ByteReadPacket ->
        val digest = MessageDigest.getInstance(hashName)!!

        val buffer = DefaultByteBufferPool.borrow()
        try {
            while (!handshakes.isEmpty) {
                val rc = handshakes.readAvailable(buffer)
                if (rc == -1) break
                buffer.flip()
                digest.update(buffer)
                buffer.clear()
            }

            return@preview digest.digest()
        } finally {
            DefaultByteBufferPool.recycle(buffer)
        }
    }

    override fun close() {
        state.release()
    }

}