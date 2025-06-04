using System;
using Xunit;

namespace Asn1FfiTests
{
    public class Asn1Tests
    {
        [Fact]
        public void TestParseGeneralizedTime()
        {
            // Arrange
            string input = "20230414123456Z";
            
            // Act
            string result = Asn1GeneralizedTime.Parse(input);
            
            // Assert
            Assert.NotNull(result);
            // Weitere Assertions basierend auf dem erwarteten Format
            Assert.Contains("2023", result);
        }
        
        [Fact]
        public void TestParseUtcTime()
        {
            // Arrange
            string input = "230414123456Z";
            
            // Act
            string result = Asn1UtcTime.Parse(input);
            
            // Assert
            Assert.NotNull(result);
            // Weitere Assertions basierend auf dem erwarteten Format
            Assert.Contains("23", result);
        }
        
        [Fact]
        public void TestInvalidGeneralizedTime()
        {
            // Arrange
            string input = "invalid";
            
            // Act & Assert
            var exception = Assert.Throws<InvalidOperationException>(() => 
                Asn1GeneralizedTime.Parse(input)
            );
        }
        
        [Fact]
        public void TestInvalidUtcTime()
        {
            // Arrange
            string input = "invalid";
            
            // Act & Assert
            var exception = Assert.Throws<InvalidOperationException>(() => 
                Asn1UtcTime.Parse(input)
            );
        }
        
        [Fact]
        public void TestNullGeneralizedTime()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                Asn1GeneralizedTime.Parse(null)
            );
        }
        
        [Fact]
        public void TestNullUtcTime()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                Asn1UtcTime.Parse(null)
            );
        }
    }
}