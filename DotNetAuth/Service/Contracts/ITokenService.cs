using DotNetAuth.Domain.Entities;

namespace DotNetAuth.Service.Contracts
{
    public interface ITokenService
    {
        Task<string> GenerateToken(ApplicationUser user);
        string GenerateRefreshToken();
    }
}
