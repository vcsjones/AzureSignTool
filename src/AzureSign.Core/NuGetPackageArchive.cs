#if NET
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace AzureSign.Core
{
    /// <summary>
    /// Reads and rewrites the ZIP structures of a NuGet package in the way the NuGet package signing
    /// specification requires. The package signature file is inserted as a stored (uncompressed) entry
    /// after the last local file entry, and its central directory header after the last central directory header.
    /// </summary>
    internal sealed class NuGetPackageArchive
    {
        internal const string SignatureFileName = ".signature.p7s";

        private const uint LocalFileHeaderSignature = 0x04034b50;
        private const uint CentralDirectoryHeaderSignature = 0x02014b50;
        private const uint EndOfCentralDirectorySignature = 0x06054b50;
        private const uint Zip64EndOfCentralDirectoryLocatorSignature = 0x07064b50;
        private const int LocalFileHeaderFixedSize = 30;
        private const int CentralDirectoryHeaderFixedSize = 46;
        private const int EndOfCentralDirectoryFixedSize = 22;
        private const int Zip64EndOfCentralDirectoryLocatorSize = 20;

        private static readonly byte[] s_signatureFileNameBytes = Encoding.ASCII.GetBytes(SignatureFileName);

        private NuGetPackageArchive(long endOfCentralDirectoryPosition, long centralDirectoryOffset, List<CentralDirectoryRecord> records, int signatureRecordIndex)
        {
            EndOfCentralDirectoryPosition = endOfCentralDirectoryPosition;
            CentralDirectoryOffset = centralDirectoryOffset;
            Records = records;
            SignatureRecordIndex = signatureRecordIndex;
        }

        public long EndOfCentralDirectoryPosition { get; }
        public long CentralDirectoryOffset { get; }
        public List<CentralDirectoryRecord> Records { get; }
        public int SignatureRecordIndex { get; }
        public bool IsSigned => SignatureRecordIndex >= 0;

        public static NuGetPackageArchive Read(Stream stream)
        {
            long eocdPosition = FindEndOfCentralDirectory(stream);
            byte[] eocd = ReadExactly(stream, eocdPosition, EndOfCentralDirectoryFixedSize);

            ushort diskNumber = BinaryPrimitives.ReadUInt16LittleEndian(eocd.AsSpan(4));
            ushort centralDirectoryDisk = BinaryPrimitives.ReadUInt16LittleEndian(eocd.AsSpan(6));
            ushort entriesOnDisk = BinaryPrimitives.ReadUInt16LittleEndian(eocd.AsSpan(8));
            ushort totalEntries = BinaryPrimitives.ReadUInt16LittleEndian(eocd.AsSpan(10));
            uint centralDirectorySize = BinaryPrimitives.ReadUInt32LittleEndian(eocd.AsSpan(12));
            uint centralDirectoryOffset = BinaryPrimitives.ReadUInt32LittleEndian(eocd.AsSpan(16));

            if (totalEntries == ushort.MaxValue || entriesOnDisk == ushort.MaxValue ||
                centralDirectorySize == uint.MaxValue || centralDirectoryOffset == uint.MaxValue ||
                HasZip64Locator(stream, eocdPosition))
            {
                throw new NotSupportedException("ZIP64 packages cannot be signed.");
            }

            if (diskNumber != 0 || centralDirectoryDisk != 0 || entriesOnDisk != totalEntries)
            {
                throw new InvalidDataException("Multi-disk archives are not supported.");
            }

            if ((long)centralDirectoryOffset + centralDirectorySize != eocdPosition)
            {
                throw new InvalidDataException("The central directory of the package is not immediately followed by the end of central directory record.");
            }

            byte[] centralDirectory = ReadExactly(stream, centralDirectoryOffset, (int)centralDirectorySize);
            List<CentralDirectoryRecord> records = new(totalEntries);
            int signatureRecordIndex = -1;
            int position = 0;

            for (int i = 0; i < totalEntries; i++)
            {
                ReadOnlySpan<byte> header = centralDirectory.AsSpan(position);

                if (header.Length < CentralDirectoryHeaderFixedSize ||
                    BinaryPrimitives.ReadUInt32LittleEndian(header) != CentralDirectoryHeaderSignature)
                {
                    throw new InvalidDataException("The package has an invalid central directory header.");
                }

                ushort fileNameLength = BinaryPrimitives.ReadUInt16LittleEndian(header.Slice(28));
                ushort extraLength = BinaryPrimitives.ReadUInt16LittleEndian(header.Slice(30));
                ushort commentLength = BinaryPrimitives.ReadUInt16LittleEndian(header.Slice(32));
                uint localHeaderOffset = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(42));
                int headerSize = CentralDirectoryHeaderFixedSize + fileNameLength + extraLength + commentLength;

                if (header.Length < headerSize)
                {
                    throw new InvalidDataException("The package has an invalid central directory header.");
                }

                // The signature file name is ASCII, so it is the same bytes whether or not the UTF-8 flag (bit 11) is set.
                // Recognize it either way so an existing signature is never missed and a second one is never added.
                bool isSignature = header.Slice(CentralDirectoryHeaderFixedSize, fileNameLength).SequenceEqual(s_signatureFileNameBytes);

                if (isSignature)
                {
                    if (signatureRecordIndex >= 0)
                    {
                        throw new InvalidDataException("The package contains multiple package signature files.");
                    }

                    signatureRecordIndex = i;
                }

                records.Add(new CentralDirectoryRecord(centralDirectory.AsSpan(position, headerSize).ToArray(), localHeaderOffset));
                position += headerSize;
            }

            if (records.Count == 0)
            {
                throw new InvalidDataException("The package does not contain any entries.");
            }

            ComputeLocalEntrySizes(records, centralDirectoryOffset);

            return new NuGetPackageArchive(eocdPosition, centralDirectoryOffset, records, signatureRecordIndex);
        }

        /// <summary>
        /// Writes a copy of the unsigned package in <paramref name="source"/> with <paramref name="signature"/> added as the package signature file.
        /// </summary>
        public void WriteWithSignature(Stream source, Stream destination, byte[] signature)
        {
            if (IsSigned)
            {
                throw new InvalidOperationException("The package is already signed.");
            }

            if (Records.Count >= ushort.MaxValue - 1)
            {
                throw new NotSupportedException("Signing the package would require ZIP64.");
            }

            uint crc = Crc32(signature);
            uint dosDateTime = ToDosDateTime(DateTime.Now);

            // All local file entries.
            CopyRange(source, destination, 0, CentralDirectoryOffset);

            long signatureLocalHeaderOffset = destination.Position;
            Span<byte> localHeader = stackalloc byte[LocalFileHeaderFixedSize];
            BinaryPrimitives.WriteUInt32LittleEndian(localHeader, LocalFileHeaderSignature);
            BinaryPrimitives.WriteUInt16LittleEndian(localHeader.Slice(4), 20); // version needed to extract
            BinaryPrimitives.WriteUInt16LittleEndian(localHeader.Slice(6), 0); // general purpose bit flag
            BinaryPrimitives.WriteUInt16LittleEndian(localHeader.Slice(8), 0); // stored
            BinaryPrimitives.WriteUInt32LittleEndian(localHeader.Slice(10), dosDateTime);
            BinaryPrimitives.WriteUInt32LittleEndian(localHeader.Slice(14), crc);
            BinaryPrimitives.WriteUInt32LittleEndian(localHeader.Slice(18), (uint)signature.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(localHeader.Slice(22), (uint)signature.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(localHeader.Slice(26), (ushort)s_signatureFileNameBytes.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(localHeader.Slice(28), 0); // extra field length
            destination.Write(localHeader);
            destination.Write(s_signatureFileNameBytes);
            destination.Write(signature);
            long signatureEntrySize = destination.Position - signatureLocalHeaderOffset;

            // All existing central directory headers.
            CopyRange(source, destination, CentralDirectoryOffset, EndOfCentralDirectoryPosition);

            Span<byte> centralHeader = stackalloc byte[CentralDirectoryHeaderFixedSize];
            BinaryPrimitives.WriteUInt32LittleEndian(centralHeader, CentralDirectoryHeaderSignature);
            BinaryPrimitives.WriteUInt16LittleEndian(centralHeader.Slice(4), 20); // version made by
            BinaryPrimitives.WriteUInt16LittleEndian(centralHeader.Slice(6), 20); // version needed to extract
            BinaryPrimitives.WriteUInt16LittleEndian(centralHeader.Slice(8), 0); // general purpose bit flag
            BinaryPrimitives.WriteUInt16LittleEndian(centralHeader.Slice(10), 0); // stored
            BinaryPrimitives.WriteUInt32LittleEndian(centralHeader.Slice(12), dosDateTime);
            BinaryPrimitives.WriteUInt32LittleEndian(centralHeader.Slice(16), crc);
            BinaryPrimitives.WriteUInt32LittleEndian(centralHeader.Slice(20), (uint)signature.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(centralHeader.Slice(24), (uint)signature.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(centralHeader.Slice(28), (ushort)s_signatureFileNameBytes.Length);
            // Extra field length, comment length, disk number, internal and external attributes are all zero.
            BinaryPrimitives.WriteUInt32LittleEndian(centralHeader.Slice(42), checked((uint)signatureLocalHeaderOffset));
            destination.Write(centralHeader);
            destination.Write(s_signatureFileNameBytes);
            long signatureCentralHeaderSize = CentralDirectoryHeaderFixedSize + s_signatureFileNameBytes.Length;

            WriteUpdatedEndOfCentralDirectory(source, destination, 1, signatureCentralHeaderSize, signatureEntrySize);
        }

        /// <summary>
        /// Writes a copy of the package in <paramref name="source"/> with the package signature file removed.
        /// </summary>
        public void WriteWithoutSignature(Stream source, Stream destination)
        {
            if (!IsSigned)
            {
                throw new InvalidOperationException("The package is not signed.");
            }

            CentralDirectoryRecord signature = Records[SignatureRecordIndex];
            long signatureEnd = signature.LocalHeaderOffset + signature.LocalEntrySize;

            CopyRange(source, destination, 0, signature.LocalHeaderOffset);
            CopyRange(source, destination, signatureEnd, CentralDirectoryOffset);

            for (int i = 0; i < Records.Count; i++)
            {
                if (i == SignatureRecordIndex)
                {
                    continue;
                }

                CentralDirectoryRecord record = Records[i];
                byte[] header = (byte[])record.Header.Clone();

                if (record.LocalHeaderOffset > signature.LocalHeaderOffset)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(42), (uint)(record.LocalHeaderOffset - signature.LocalEntrySize));
                }

                destination.Write(header);
            }

            WriteUpdatedEndOfCentralDirectory(source, destination, -1, -signature.Header.Length, -signature.LocalEntrySize);
        }

        private static void WriteUpdatedEndOfCentralDirectory(Stream source, Stream destination, int entryCountChange, long centralDirectorySizeChange, long centralDirectoryOffsetChange)
        {
            source.Position = FindEndOfCentralDirectory(source);
            byte[] eocd = ReadExactly(source, source.Position, EndOfCentralDirectoryFixedSize);
            Span<byte> span = eocd;

            BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(8), (ushort)(BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(8)) + entryCountChange));
            BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(10), (ushort)(BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(10)) + entryCountChange));
            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(12), checked((uint)(BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(12)) + centralDirectorySizeChange)));
            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(16), checked((uint)(BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(16)) + centralDirectoryOffsetChange)));
            destination.Write(eocd);

            // The archive comment, if any.
            CopyRange(source, destination, source.Position, source.Length);
        }

        private static void ComputeLocalEntrySizes(List<CentralDirectoryRecord> records, long centralDirectoryOffset)
        {
            List<CentralDirectoryRecord> ordered = new(records);
            ordered.Sort((x, y) => x.LocalHeaderOffset.CompareTo(y.LocalHeaderOffset));

            for (int i = 0; i < ordered.Count; i++)
            {
                long end = i + 1 < ordered.Count ? ordered[i + 1].LocalHeaderOffset : centralDirectoryOffset;
                ordered[i].LocalEntrySize = end - ordered[i].LocalHeaderOffset;
            }
        }

        private static bool HasZip64Locator(Stream stream, long eocdPosition)
        {
            if (eocdPosition < Zip64EndOfCentralDirectoryLocatorSize)
            {
                return false;
            }

            byte[] locator = ReadExactly(stream, eocdPosition - Zip64EndOfCentralDirectoryLocatorSize, 4);
            return BinaryPrimitives.ReadUInt32LittleEndian(locator) == Zip64EndOfCentralDirectoryLocatorSignature;
        }

        private static long FindEndOfCentralDirectory(Stream stream)
        {
            if (stream.Length < EndOfCentralDirectoryFixedSize)
            {
                throw new InvalidDataException("The file is not a valid ZIP archive.");
            }

            // The end of central directory record is followed by a variable length comment of at most 65535 bytes.
            int searchLength = (int)Math.Min(stream.Length, EndOfCentralDirectoryFixedSize + ushort.MaxValue);
            long searchStart = stream.Length - searchLength;
            byte[] buffer = ReadExactly(stream, searchStart, searchLength);

            for (int i = searchLength - EndOfCentralDirectoryFixedSize; i >= 0; i--)
            {
                if (BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(i)) == EndOfCentralDirectorySignature &&
                    BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(i + 20)) == searchLength - i - EndOfCentralDirectoryFixedSize)
                {
                    return searchStart + i;
                }
            }

            throw new InvalidDataException("The file is not a valid ZIP archive.");
        }

        private static byte[] ReadExactly(Stream stream, long position, int count)
        {
            byte[] buffer = new byte[count];
            stream.Position = position;
            stream.ReadExactly(buffer);
            return buffer;
        }

        private static void CopyRange(Stream source, Stream destination, long start, long end)
        {
            source.Position = start;
            byte[] buffer = new byte[81920];
            long remaining = end - start;

            while (remaining > 0)
            {
                int read = source.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));

                if (read == 0)
                {
                    throw new EndOfStreamException();
                }

                destination.Write(buffer, 0, read);
                remaining -= read;
            }
        }

        private static uint Crc32(ReadOnlySpan<byte> data)
        {
            uint crc = 0xFFFFFFFF;

            foreach (byte b in data)
            {
                crc ^= b;

                for (int i = 0; i < 8; i++)
                {
                    crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320 : crc >> 1;
                }
            }

            return ~crc;
        }

        private static uint ToDosDateTime(DateTime dateTime)
        {
            int year = Math.Clamp(dateTime.Year, 1980, 2107);
            int value = (year - 1980) & 0x7F;
            value = (value << 4) + dateTime.Month;
            value = (value << 5) + dateTime.Day;
            value = (value << 5) + dateTime.Hour;
            value = (value << 6) + dateTime.Minute;
            value = (value << 5) + (dateTime.Second / 2);
            return (uint)value;
        }

        internal sealed class CentralDirectoryRecord
        {
            public CentralDirectoryRecord(byte[] header, long localHeaderOffset)
            {
                Header = header;
                LocalHeaderOffset = localHeaderOffset;
            }

            public byte[] Header { get; }
            public long LocalHeaderOffset { get; }
            public long LocalEntrySize { get; set; }
        }
    }
}
#endif
