namespace SafeVault.Security
{
    /// <summary>
    /// Security testing utilities for validation and XSS protection
    /// </summary>
    public static class SecurityTester
    {
        public static void RunXssTests()
        {
            var testCases = new Dictionary<string, bool>
            {
                { "<script>alert('XSS');</script>", false },
                { "javascript:alert('XSS')", false },
                { "<img src='x' onerror='alert(1)'>", false },
                { "Regular text input", true },
                { "Hello123!@#", true }
            };

            foreach (var test in testCases)
            {
                bool result = XssProtection.IsValidInput(test.Key);
                Console.WriteLine($"Test case: {test.Key}");
                Console.WriteLine($"Expected: {test.Value}, Got: {result}");
                Console.WriteLine($"Test {(result == test.Value ? "Passed" : "Failed")}\n");
            }
        }

        public static void RunPasswordTests()
        {
            // Test password hashing and verification
            string password = "TestPassword123!";
            var (hash, salt) = PasswordHasher.HashPassword(password);

            bool validPassword = PasswordHasher.VerifyPassword(password, hash, salt);
            bool invalidPassword = PasswordHasher.VerifyPassword("WrongPassword", hash, salt);

            Console.WriteLine($"Valid password test: {(validPassword ? "Passed" : "Failed")}");
            Console.WriteLine($"Invalid password test: {(!invalidPassword ? "Passed" : "Failed")}");
        }

        public static void RunInputValidationTests()
        {
            var testCases = new Dictionary<string, bool>
            {
                { "ValidInput123", true },
                { "Invalid@Input", false },
                { "", false },
                { new string('a', 1001), false },
                { "Valid-Input", true }
            };

            foreach (var test in testCases)
            {
                bool result = InputValidator.IsValidInput(test.Key, "-");
                Console.WriteLine($"Test case: {test.Key}");
                Console.WriteLine($"Expected: {test.Value}, Got: {result}");
                Console.WriteLine($"Test {(result == test.Value ? "Passed" : "Failed")}\n");
            }
        }
    }
}