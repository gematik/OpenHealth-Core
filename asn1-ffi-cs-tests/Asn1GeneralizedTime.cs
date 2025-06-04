using System;
using System.Runtime.InteropServices;

namespace Asn1FfiTests
{
    /// <summary>
    /// C# Wrapper für die asn1_ffi Generalized Time Funktionalität.
    /// </summary>
    public class Asn1GeneralizedTime
    {
        /// <summary>
        /// Parst einen ASN.1 GeneralizedTime-String.
        /// </summary>
        /// <param name="input">Der zu parsende Zeitstring im ASN.1 GeneralizedTime Format (z.B. "20230414123456Z")</param>
        /// <returns>Eine formatierte Darstellung des Zeitpunkts</returns>
        /// <exception cref="InvalidOperationException">Wird geworfen, wenn das Parsen fehlschlägt</exception>
        public static string Parse(string input)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentNullException(nameof(input));

            IntPtr resultPtr = Asn1Native.parse_generalized_time(input, input.Length);
            
            if (resultPtr == IntPtr.Zero)
                throw new InvalidOperationException("Fehler beim Parsen des GeneralizedTime-Formats");
                
            string result = Marshal.PtrToStringAnsi(resultPtr);
            
            // Falls Ihre FFI-Bibliothek eine Methode zum Freigeben des Speichers bereitstellt:
            // Asn1Native.free_string(resultPtr);
            
            return result;
        }
    }
}