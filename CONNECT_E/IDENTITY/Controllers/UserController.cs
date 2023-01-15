using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using CONNECT_E.COMMON.ENTITIES;

namespace CONNECT_E.IDENTITY.CONTROLLERS;


public class ResponseJson
{
    public string token { get; set; }
    public string username { get; set; }
}

[Route("api/[controller]")]
[ApiController]
[AllowAnonymous]
public class UsersController : ControllerBase
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IConfiguration _configuration;

    public UsersController(
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        RoleManager<IdentityRole> roleManager,
        IConfiguration configuration)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _roleManager = roleManager;
        _configuration = configuration;
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> GetAll()
    {
        try
        {
            IEnumerable<IdentityUser> users = _userManager.Users;

            return Ok(value: users);
        }
        catch (Exception ex)
        {
            return NotFound();
        }
    }

    [HttpGet]
    [Route("{userName}")]
    public async Task<IActionResult> GetByUserName(string userName)
    {
        try
        {
            IdentityUser user = await _userManager.FindByNameAsync(userName);

            if (user != null)
            {
                return Ok(user);
            }

            return Ok();

        }
        catch (Exception ex)
        {
            return NotFound();
        }
    }

    [Route("register")]
    [AllowAnonymous]
    [HttpPost]
    public async Task<IActionResult> Register([FromBody] User user)
    {
        try
        {
            string userName = user.UserName;
            string password = user.Password;

            IdentityUser userIdentity = new IdentityUser
            {
                ///*Email*/ = userName,
                UserName = userName.ToUpper(),
            };

            IdentityResult identityResult = await _userManager.CreateAsync(userIdentity, password);

            if (identityResult.Succeeded)
            {
                IdentityResult roleResult = await _userManager.AddToRoleAsync(userIdentity, "Utilisateur");

                if (roleResult.Succeeded)
                {
                    //_userManager.AddToRoleAsync(userIdentity, "Utilisateur").Wait();
                    return Ok(new { identityResult.Succeeded });
                }
                else
                {
                    string errorMessage = "Une erreur est survenue lors de la création du compte";

                    foreach (var error in identityResult.Errors)
                    {
                        errorMessage += Environment.NewLine;

                        if (error.Code == "DuplicateUserName")
                        {
                            errorMessage += "L'utilisateur existe déjà";
                        }
                        else
                        {
                            errorMessage += $"Error Code : {error.Code} - {error.Description}";
                        }
                    }

                    return StatusCode(StatusCodes.Status500InternalServerError, errorMessage);
                }

            }
            else
            {
                string errorMessage = "Une erreur est survenue lors de la création du compte";

                foreach (var error in identityResult.Errors)
                {
                    errorMessage += Environment.NewLine;



                    if (error.Code == "DuplicateUserName")
                    {
                        errorMessage += "L'utilisateur existe déjà";
                    }
                    else if (error.Code == "PasswordRequiresNonAlphanumeric"
                        || error.Code == "PasswordRequiresUpper"
                        || error.Code == "PasswordRequiresDigit"
                        || error.Code == "PasswordRequiresLower")
                    {
                        errorMessage += "Le mot de passe doit contenir entre 8 et 20 caractères " +
                            "avec au moins 1 majuscule, 1 minuscule, 1 chiffre et 1 caractère non alphanumérique type symbole.";
                    }
                    else
                    {
                        errorMessage += $"Error Code : {error.Code} - {error.Description}";
                    }
                }

                return StatusCode(StatusCodes.Status500InternalServerError, errorMessage);
            }
        }
        catch (Exception ex)
        {
            return StatusCode(StatusCodes.Status400BadRequest, ex.ToString());
        }
    }

    [HttpPost]
    [Route("signin")]
    public async Task<IActionResult> SignIn([FromBody] User user)
    {
        string userName = user.UserName;
        string password = user.Password;

        try
        {
            Microsoft.AspNetCore.Identity.SignInResult signInResult = await _signInManager.PasswordSignInAsync(userName, password, false, false);

            if (signInResult.Succeeded)
            {
                IdentityUser identityUser = await _userManager.FindByNameAsync(userName);
                string JSONWebToken = await GenerateJSONWebToken(identityUser);

                return Ok(JSONWebToken);
            }
            else
            {
                return Unauthorized(user);
                throw new UnauthorizedAccessException($"L'utilisateur {userName.ToUpper()} n'a pas été autorisé à se connecter !.");
            }

        }
        catch (Exception ex)
        {
            return Unauthorized(user);
        }
    }



    [NonAction]
    [ApiExplorerSettings(IgnoreApi = true)]
    private async Task<string> GenerateJSONWebToken(IdentityUser identityUser)
    {
        try
        {
            SymmetricSecurityKey symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));

            SigningCredentials credentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            List<Claim> claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, identityUser.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, identityUser.Id)
        };

            IList<string> roleNames = await _userManager.GetRolesAsync(identityUser);
            claims.AddRange(roleNames.Select(roleName => new Claim(ClaimsIdentity.DefaultRoleClaimType, roleName)));

            JwtSecurityToken bearerToken = new JwtSecurityToken
            (
                _configuration["Jwt: Issuer"],
                _configuration["Jwt: Issuer"],
                claims,
                null,
                expires: DateTime.UtcNow.AddDays(1),
                credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(bearerToken);
        }
        catch (Exception ex)
        {
            return string.Empty;
        }
    }
}

[Route("api/[controller]")]
[ApiController]
public class RolesController : ControllerBase
{
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly UserManager<IdentityUser> _userManager;

    public class ParameterPost
    {
        public string userid { get; set; }
        public string roleid { get; set; }
    }

    public RolesController(RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager)
    {
        _roleManager = roleManager;
        _userManager = userManager;
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        try
        {
            IEnumerable<IdentityRole> roles = _roleManager.Roles.OrderBy(r => r.Name);
            return Ok(value: roles);
        }
        catch (Exception ex)
        {
            return NotFound();
        }
    }

    [HttpGet]
    [Route("user/{id}")]
    public async Task<ActionResult> GetRolesByUser(string id)
    {

        try
        {
            Guid.TryParse(id, out Guid guidId);

            var user = await _userManager.FindByIdAsync(id);

            var roles = _roleManager.Roles;

            IList<string> userRolesString = await _userManager.GetRolesAsync(user);

            return Ok(userRolesString);

        }
        catch (Exception ex)
        {
            return NotFound();
        }
    }

    [HttpPost]
    public async Task<IActionResult> CreateRole([FromBody] Role role)
    {
        try
        {
            var isRoleExist = await _roleManager.RoleExistsAsync(role.Name);

            if (!isRoleExist)
            {
                IdentityRole roleIdentity = new IdentityRole
                {
                    Name = role.Name
                };

                IdentityResult identityResult = await _roleManager.CreateAsync(roleIdentity);

                if (identityResult.Succeeded == true)
                {
                    return Ok(new { identityResult.Succeeded });
                }
                else
                {
                    string errorMessage = "Une erreur est survenue lors de la création du role";

                    foreach (var error in identityResult.Errors)
                    {
                        errorMessage += Environment.NewLine;
                        errorMessage += $"Error Code : {error.Code} - {error.Description}";
                    }

                    return StatusCode(StatusCodes.Status500InternalServerError, errorMessage);
                }
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError, "Ce role existe déjà !");
            }
        }
        catch (Exception ex)
        {
            return StatusCode(StatusCodes.Status400BadRequest, ex.ToString());
        }
    }

    [HttpPost]
    [Route("user/addrole")]
    //[Route("user/addrole/{userid}/{roleid}")]
    public async Task<IActionResult> AddRoleToUser([FromBody] ParameterPost parameters)
    {
        try
        {
            //----- Recherche du IdentityUser -----
            IdentityUser user = await _userManager.FindByIdAsync(parameters.userid);

            if (user == null) return BadRequest();

            if (user != null)
            {
                //----- Recherche du IdentityRole à ajouter -----
                IdentityRole role = await _roleManager.FindByIdAsync(parameters.roleid);

                if (role == null) return BadRequest();

                if (role != null)
                {
                    IdentityResult roleResult = await _userManager.AddToRoleAsync(user, role.Name);

                    if (roleResult.Succeeded)
                    {
                        return Ok();
                    }
                }

                return BadRequest();
            }

            return BadRequest();
        }
        catch (Exception ex)
        {
            return StatusCode(StatusCodes.Status400BadRequest, ex.ToString());
        }
    }

    [HttpPost]
    [Route("user/remove")]
    public async Task<IActionResult> DeleteRoleFromUser([FromBody] ParameterPost parameters)
    {
        try
        {
            //----- Recherche du IdentityUser -----
            IdentityUser user = await _userManager.FindByIdAsync(parameters.userid);

            //----- Recherche du IdentityRole à ajouter -----
            IdentityRole role = await _roleManager.FindByIdAsync(parameters.roleid);

            if (user == null || role == null) return BadRequest();

            IdentityResult identityResult = await _userManager.RemoveFromRoleAsync(user, role.Name);

            if (identityResult.Succeeded)
            {
                return Ok();
            }

            return BadRequest();

        }
        catch (Exception ex)
        {
            return StatusCode(StatusCodes.Status400BadRequest, ex.ToString());
        }
    }
}
