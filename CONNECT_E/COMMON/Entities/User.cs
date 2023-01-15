

using System.ComponentModel.DataAnnotations;

namespace CONNECT_E.COMMON.ENTITIES
{
    public class User
    {
        [Required]
        //[EmailAddress]
        [Display(Name = "Login")]
        public string UserName { get; set; }

        [Required]
        [StringLength(20, ErrorMessage = "Le mot de passe doit être compris entre {2} et {1} caractères", MinimumLength = 8)]
        [DataType(DataType.Password)]
        [Display(Name = "Mot de passe")]
        public string Password { get; set; }
    }
}
