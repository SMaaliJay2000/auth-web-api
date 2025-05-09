using DotNetAuth.Domain.Constructs;
using DotNetAuth.Infrastructure.Context;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace DotNetAuth.Extentions
{
    public static partial class ApplicationService
    {
        // Allow any origin, method and header
        public static void ConfigureCors(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddCors(options =>
            {
                options.AddPolicy("CorsPolicy", builder =>
                {
                    builder.WithOrigins(configuration.GetSection("AllowedOrigins").Get<string[]>()!)
                       .AllowAnyMethod()
                       .AllowAnyHeader()
                       .AllowCredentials(); // Allow cookies
                    });
            });
        }

        public static void ConfigureIdentity(this IServiceCollection services)
        {
            services.AddIdentityCore<IdentityUser>(o =>
            {
                o.Password.RequireDigit = false;
                o.Password.RequireLowercase = false;
                o.Password.RequireUppercase = false;
                o.Password.RequireNonAlphanumeric = false;
                o.Password.RequiredLength = 6;
                o.User.RequireUniqueEmail = true;
            }).AddEntityFrameworkStores<ApplicationDbContext>()
              .AddDefaultTokenProviders();
        }

        public static void ConfigureJwt(this IServiceCollection services, IConfiguration configuration)
        {
            var jwtSettings = configuration.GetSection("JwtSettings").Get<JwtSettings>();
            if (jwtSettings == null || string.IsNullOrEmpty(jwtSettings.Key))

            {
                throw new InvalidOperationException("JWT secret key is not configured.");
            }

            var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Key));
            services.AddAuthentication(o =>
            {
                o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(o =>
            {
                o.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtSettings.ValidIssuer,
                    ValidAudience = jwtSettings.ValidAudience,
                    IssuerSigningKey = secretKey,

                    ClockSkew = TimeSpan.Zero
                };
                o.Events = new JwtBearerEvents
                {
                    OnChallenge = context =>
                    {
                        context.HandleResponse();
                        context.Response.StatusCode = 401;
                        context.Response.ContentType = "application/json";
                        var result = System.Text.Json.JsonSerializer.Serialize(new
                        {
                            message = "You are not authorized to access this resource. Please authenticate."
                        });
                        return context.Response.WriteAsync(result);
                    },
                };
            });
        }

    }
}
