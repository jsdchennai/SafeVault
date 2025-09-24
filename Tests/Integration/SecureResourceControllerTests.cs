using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using Xunit;
using SafeVault.Constants;

namespace SafeVault.Tests.Integration
{
    public class SecureResourceControllerTests : IClassFixture<TestWebApplicationFactory>, IDisposable
    {
        private readonly HttpClient _client;
        private readonly TestWebApplicationFactory _factory;

        public SecureResourceControllerTests(TestWebApplicationFactory factory)
        {
            _factory = factory;
            _client = _factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false
            });
        }

        [Fact]
        public async Task GetPublicResource_ShouldAlwaysBeAccessible()
        {
            // Act
            var response = await _client.GetAsync("/api/SecureResource/public");

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Theory]
        [InlineData(RoleNames.User)]
        [InlineData(RoleNames.Admin)]
        public async Task GetUserResource_WithValidRole_ShouldAllowAccess(string role)
        {
            // Arrange
            _client.DefaultRequestHeaders.Add("Test-Roles", role);

            // Act
            var response = await _client.GetAsync("/api/SecureResource/user");

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task GetUserResource_WithoutRole_ShouldDenyAccess()
        {
            // Act
            var response = await _client.GetAsync("/api/SecureResource/user");

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task GetAdminResource_WithAdminRole_ShouldAllowAccess()
        {
            // Arrange
            _client.DefaultRequestHeaders.Add("Test-Roles", RoleNames.Admin);

            // Act
            var response = await _client.GetAsync("/api/SecureResource/admin");

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Theory]
        [InlineData(RoleNames.User)]
        [InlineData(RoleNames.Guest)]
        public async Task GetAdminResource_WithNonAdminRole_ShouldDenyAccess(string role)
        {
            // Arrange
            _client.DefaultRequestHeaders.Add("Test-Roles", role);

            // Act
            var response = await _client.GetAsync("/api/SecureResource/admin");

            // Assert
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task GetVerifiedResource_ShouldRequireVerifiedEmail(bool isVerified)
        {
            // Arrange
            _client.DefaultRequestHeaders.Add("Test-Roles", RoleNames.User);
            _client.DefaultRequestHeaders.Add("Test-EmailVerified", isVerified.ToString());

            // Act
            var response = await _client.GetAsync("/api/SecureResource/verified");

            // Assert
            Assert.Equal(
                isVerified ? HttpStatusCode.OK : HttpStatusCode.Forbidden,
                response.StatusCode
            );
        }

        [Fact]
        public async Task GetElevatedResource_WithAdminRole_ShouldAllowAccess()
        {
            // Arrange
            _client.DefaultRequestHeaders.Add("Test-Roles", RoleNames.Admin);

            // Act
            var response = await _client.GetAsync("/api/SecureResource/elevated");

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task GetElevatedResource_WithUserRole_ShouldAllowAccess()
        {
            // Arrange
            _client.DefaultRequestHeaders.Add("Test-Roles", RoleNames.User);

            // Act
            var response = await _client.GetAsync("/api/SecureResource/elevated");

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task GetElevatedResource_WithGuestRole_ShouldDenyAccess()
        {
            // Arrange
            _client.DefaultRequestHeaders.Add("Test-Roles", RoleNames.Guest);

            // Act
            var response = await _client.GetAsync("/api/SecureResource/elevated");

            // Assert
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [Fact]
        public async Task GetCombinedResource_WithAllRequirements_ShouldAllowAccess()
        {
            // Arrange
            _client.DefaultRequestHeaders.Add("Test-Roles", RoleNames.Admin);
            _client.DefaultRequestHeaders.Add("Test-EmailVerified", "true");

            // Act
            var response = await _client.GetAsync("/api/SecureResource/combined");

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Theory]
        [InlineData(RoleNames.Admin, false)]
        [InlineData(RoleNames.User, true)]
        public async Task GetCombinedResource_WithPartialRequirements_ShouldDenyAccess(string role, bool emailVerified)
        {
            // Arrange
            _client.DefaultRequestHeaders.Add("Test-Roles", role);
            _client.DefaultRequestHeaders.Add("Test-EmailVerified", emailVerified.ToString());

            // Act
            var response = await _client.GetAsync("/api/SecureResource/combined");

            // Assert
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        public void Dispose()
        {
            _client?.Dispose();
            _factory?.Dispose();
        }
    }
}