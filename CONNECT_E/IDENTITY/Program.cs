
using CONNECT_E.EFCORE.DBCONTEXT;
using CONNECT_E.IDENTITY.EXTENSION_METHODS;
using CONNECT_E.IDENTITY.INITIALIZEDATAS;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

try
{ 

    var builder = WebApplication.CreateBuilder(args);

    // Add services to the container.
    builder.Services.AddCors(option =>
    {
        option.AddPolicy("CorsPolicy",
            builder =>
            builder
                 .WithOrigins("https://localhost:7193")
                .AllowAnyOrigin()
                .AllowAnyMethod()
                .AllowAnyHeader());
    });

    builder.Services.AddDbContext<IdentityDbContext>(options =>
            options.UseSqlServer(builder.Configuration.GetConnectionString("IdentityConnection"), b => b.MigrationsAssembly("MIGRATIONS")));

    builder.Services.AddCustomSecurity(builder.Configuration);

    builder.Services.AddDefaultIdentity<IdentityUser>()
        .AddRoles<IdentityRole>()
        .AddEntityFrameworkStores<IdentityDbContext>();

    builder.Services.AddRouting(option => option.LowercaseUrls = true);


    builder.Services.AddControllers();

    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();

    var app = builder.Build();

    // Migrate database
    using (var scope = app.Services.CreateScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        db.Database.Migrate();
    }

    app.UseSwagger();
    app.UseSwaggerUI();

    app.UseHttpsRedirection();

    app.UseRouting();

    app.UseCors("CorsPolicy");

    app.UseAuthentication();

    app.UseAuthorization();

    app.UseEndpoints(endpoints =>
    {
        endpoints.MapDefaultControllerRoute().RequireAuthorization();
    });

    InitializeData.Seed(app);


    app.Run();

}
catch (Exception ex)
{
    Console.WriteLine(ex.Message.ToString());
}


return 0;
