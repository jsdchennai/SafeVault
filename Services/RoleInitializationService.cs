using Microsoft.AspNetCore.Identity;
using SafeVault.Constants;
using SafeVault.Models;

namespace SafeVault.Services
{
    public class RoleInitializationService
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;

        public RoleInitializationService(
            RoleManager<IdentityRole> roleManager,
            UserManager<ApplicationUser> userManager,
            IConfiguration configuration)
        {
            _roleManager = roleManager;
            _userManager = userManager;
            _configuration = configuration;
        }

        public async Task InitializeRolesAsync()
        {
            // Create roles if they don't exist
            foreach (var roleName in RoleNames.AllRoles)
            {
                if (!await _roleManager.RoleExistsAsync(roleName))
                {
                    await _roleManager.CreateAsync(new IdentityRole(roleName));
                }
            }

            // Create default admin user if configured
            var adminEmail = _configuration["DefaultAdmin:Email"];
            var adminPassword = _configuration["DefaultAdmin:Password"];

            if (!string.IsNullOrEmpty(adminEmail) && !string.IsNullOrEmpty(adminPassword))
            {
                var adminUser = await _userManager.FindByEmailAsync(adminEmail);

                if (adminUser == null)
                {
                    adminUser = new ApplicationUser
                    {
                        UserName = adminEmail,
                        Email = adminEmail,
                        EmailConfirmed = true,
                        CreatedAt = DateTime.UtcNow
                    };

                    var result = await _userManager.CreateAsync(adminUser, adminPassword);
                    if (result.Succeeded)
                    {
                        await _userManager.AddToRoleAsync(adminUser, RoleNames.Admin);
                    }
                }
                else if (!await _userManager.IsInRoleAsync(adminUser, RoleNames.Admin))
                {
                    await _userManager.AddToRoleAsync(adminUser, RoleNames.Admin);
                }
            }
        }
    }
}