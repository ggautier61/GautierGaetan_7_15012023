using CONNECT_E.IDENTITY.CONFIGURATIONS;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace CONNECT_E.IDENTITY.EXTENSION_METHODS
{
    public static class SecurityMethods
    {

        #region Variables
        public const string CorsPolicy = "CorsPolicy";
        #endregion

        #region Public Methods

        public static void AddCustomSecurity(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddCustomAuthentification(configuration);
        }
        public static void AddCustomCors(this IServiceCollection services, IConfiguration configuration)
        {
            //CorsOption corsOption = new CorsOption();
            //configuration.GetSection("Cors").Bind(corsOption);

            services.AddCors(option =>
            {
                option.AddPolicy(CorsPolicy,
                    builder =>
                    {
                        builder.WithOrigins("https://localhost:7193", "https://localhost:5001")
                        //builder.WithOrigins(corsOption.OriginFront, corsOption.OriginAPI)
                        //builder.AllowAnyOrigin()
                            .AllowAnyHeader()
                            .AllowAnyMethod();
                    });
            });

        }

        public static void AddCustomAuthentification(this IServiceCollection services, IConfiguration configuration)
        {
            SecurityOption securityOption = new SecurityOption();
            configuration.GetSection("Jwt").Bind(securityOption);

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                string maClef = securityOption.Key;
                options.SaveToken = true;
                options.TokenValidationParameters = new TokenValidationParameters()
                {
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(securityOption.Key)),
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ValidateActor = false,
                    ValidateIssuer = false
                };

            });

        }

        #endregion
    }
}
