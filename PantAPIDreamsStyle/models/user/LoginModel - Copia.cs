using System.ComponentModel.DataAnnotations;

namespace PantAPIDreamsStyle.models.user
{
    public class UpdateDataUserModel
    {
        [Required]
        public string IdUser { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Name { get; set; }

        [Required]
        public string Lastname { get; set; }
    }
}
