
import de.gematik.openhealth.asn1.Asn1GeneralizedTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class Asn1GeneralizedTimeTest {
    @Test
    fun testValidGeneralizedTime() {
        val expected = """Asn1GeneralizedTime { year: 2023, month: 5, day: 17, hour: 12, minute: Some(34), second: Some(56), fraction_of_second: None, offset: None }"""
        val actual = Asn1GeneralizedTime.parse("20230517123456Z")
        assertEquals(expected, actual)
    }

    @Test
    fun testGeneralizedTimeWithFraction() {
        val expected = """Asn1GeneralizedTime { year: 2023, month: 5, day: 17, hour: 12, minute: Some(34), second: Some(56), fraction_of_second: Some(123), offset: None }"""
        val actual = Asn1GeneralizedTime.parse("20230517123456.123Z")
        assertEquals(expected, actual)
    }

    @Test
    fun testInvalidGeneralizedTime() {
        assertFailsWith<IllegalArgumentException> {
            Asn1GeneralizedTime.parse("invalid")
        }
    }
}