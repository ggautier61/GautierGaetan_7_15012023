
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace CONNECT_E.COMMON.ENTITIES
{
    public class Role
    {
        #region Properties

        [JsonIgnore]
        public Guid Id { get; set; }

        [Required]
        public string? Name { get; set; }

        #endregion

    }

}
