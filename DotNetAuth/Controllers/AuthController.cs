using DotNetAuth.Domain.Constructs;
using DotNetAuth.Service;
using DotNetAuth.Service.Contracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace DotNetAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userService;

        public AuthController(IUserService userService)
        {
            _userService = userService;
        }


        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> RegisterAsync([FromBody] UserRegisterRequest request)
        {
            var response = await _userService.RegisterAsync(request);
            return Ok(response);
        }


        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> LoginAsync([FromBody] UserLoginRequest request)
        {
            var response = await _userService.LoginAsync(request);

            // Set refresh token in HttpOnly cookie
            SetRefreshTokenCookie(response.RefreshToken);

            // Do not return refresh token in response
            response.RefreshToken = null;

            return Ok(response);
        }


        [HttpPost("logout")]
        public async Task<IActionResult> Logout(Guid id)
        {
            await _userService.LogoutAsync(id);
            // Remove cookie
            Response.Cookies.Delete("refreshToken");
            return Ok(new { message = "Logged out successfully" });
        }


        // Get user by id
        [HttpGet("user/{id}")]
        [Authorize]
        public async Task<IActionResult> GetUserAsync(Guid id)
        {
            var response = await _userService.GetByIdAsync(id);
            return Ok(response);
        }


        // Get all users
        [HttpGet("users")]
        [AllowAnonymous]
        [Authorize]
        public async Task<IActionResult> GetAllAsync()
        {
            var response = await _userService.GetAllAsync();
            return Ok(response);
        }


        // Get new access token from refresh token
        [HttpPost("refresh-token")]
        [Authorize]
        public async Task<IActionResult> RefreshTokenAsync()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(refreshToken))
            {
                return Unauthorized("Refresh token is missing.");
            }

            var response = await _userService.RefreshTokenAsync(new RefreshTokenRequest { RefreshToken = refreshToken });

            // Optionally renew the refresh token cookie
            SetRefreshTokenCookie(refreshToken);

            return Ok(response);
        }


        // Remove refresh token
        [HttpPost("revoke-refresh-token")]
        [Authorize]
        public async Task<IActionResult> RevokeTokenAsync()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(refreshToken))
            {
                return BadRequest("Refresh token is missing.");
            }

            var response = await _userService.RevokeRefreshToken(new RefreshTokenRequest { RefreshToken = refreshToken });

            if (response != null && response.Message == "Refresh token revoked successfully")
            {
                Response.Cookies.Delete("refreshToken");
                return Ok(response);
            }

            return BadRequest(response);
        }


        [HttpGet("current-user")]
        [Authorize]
        public async Task<IActionResult> GetCurrentUserAsync()
        {
            var response = await _userService.GetCurrentUserAsync();
            return Ok(response);
        }


        // Update user by id
        [HttpPut("update/{id}")] 
        [Authorize]
        public async Task<IActionResult> UpdateAsync(Guid id, [FromBody] UpdateUserRequest request)
        {
            var response = await _userService.UpdateAsync(id, request);
            return Ok(response);
        }


        // Delete user
        [HttpDelete("delete/{id}")] 
        [Authorize]
        public async Task<IActionResult> DeleteAsync(Guid id)
        {
            await _userService.DeleteAsync(id);
            return Ok("User deleted successfully");
        }


        private void SetRefreshTokenCookie(string refreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(2)
            };
            Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }
    }
}
