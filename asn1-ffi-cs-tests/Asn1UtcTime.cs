using System;
using System.Runtime.InteropServices;

namespace Asn1FfiTests
{
    /// <summary>
    /// C# Wrapper für die asn1_ffi UTCTime Funktionalität.
    /// </summary>
    public class Asn1UtcTime
    {
        /// <summary>
        /// Parst einen ASN.1 UTCTime-String.
        /// </summary>
        /// <param name="input">Der zu parsende Zeitstring im ASN.1 UTCTime Format (z.B. "230414123456Z")</param>
        /// <returns>Eine formatierte Darstellung des Zeitpunkts</returns>
        /// <exception cref="InvalidOperationException">Wird geworfen, wenn das Parsen fehlschlägt</exception>
        public static string Parse(string input)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentNullException(nameof(input));

            IntPtr resultPtr = Asn1Native.parse_utc_time(input, input.Length);

            if (resultPtr == IntPtr.Zero)
                throw new InvalidOperationException("Fehler beim Parsen des UTCTime-Formats");

            string result = Asn1Native.PtrToString(resultPtr);

            // Falls Ihre FFI-Bibliothek eine Methode zum Freigeben des Speichers bereitstellt:
            // Asn1Native.free_string(resultPtr);

            return result;
        }
    }
}