using Microsoft.AspNetCore.Identity;
using CONNECT_E.EFCORE.DBCONTEXT;

namespace CONNECT_E.IDENTITY.INITIALIZEDATAS
{
    public class InitializeData
    {
        public static void Seed(IApplicationBuilder applicationBuilder)
        {
            using(var scope = applicationBuilder.ApplicationServices.CreateScope())
            {
				var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
				
				//check roles exist
				IdentityRole? role = db.Roles.Where(obj => obj.Name == "Administrateur").FirstOrDefault();
				if (role == null)
				{
					db.Roles.Add(new IdentityRole { Name = "Administrateur", NormalizedName = "ADMINISTRATEUR" });
				}

                role = db.Roles.Where(obj => obj.Name == "Utilisateur").FirstOrDefault();
                if (role == null)
                {
                    db.Roles.Add(new IdentityRole { Name = "Utilisateur", NormalizedName = "UTILISATEUR" });
                }

                
                
				db.SaveChanges();

			}
        }

    }
}
