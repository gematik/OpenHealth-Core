using System;
using System.Runtime.InteropServices;

namespace Asn1FfiTests
{
    /// <summary>
    /// Stellt P/Invoke-Definitionen für die native asn1_ffi Bibliothek bereit.
    /// </summary>
    public static class Asn1Native
    {
        // Plattformspezifischer Bibliotheksname
        #if __MACOS__
            private const string LibraryName = "libasn1_ffi.dylib";
        #elif __LINUX__
            private const string LibraryName = "libasn1_ffi.so";
        #elif _WIN32 || _WIN64
            private const string LibraryName = "asn1_ffi.dll";
        #else
            private const string LibraryName = "asn1_ffi";
        #endif

        [DllImport("asn1_ffi", CallingConvention = CallingConvention.Cdecl, EntryPoint = "asn1_utc_time_parse")]
        public static extern IntPtr parse_utc_time(string input, int inputLength);
        
        [DllImport("asn1_ffi", CallingConvention = CallingConvention.Cdecl, EntryPoint = "asn1_generalized_time_parse")]
        public static extern IntPtr parse_generalized_time(string input, int inputLength);

        /// <summary>
        /// Optional: Gibt den Speicher eines von der nativen Bibliothek zurückgegebenen Strings frei.
        /// </summary>
        /// <param name="ptr">Der freizugebende String-Pointer</param>
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void free_string(IntPtr ptr);

        /// <summary>
        /// Konvertiert einen nativen String-Pointer in einen C#-String.
        /// </summary>
        /// <param name="ptr">Der zu konvertierende Pointer</param>
        /// <returns>Der konvertierte String oder null, wenn der Pointer null ist</returns>
        public static string PtrToString(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
                return null;

            return Marshal.PtrToStringAnsi(ptr);
        }
    }
}