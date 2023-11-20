using System.ComponentModel.DataAnnotations;

namespace PantAPIDreamsStyle.models.user
{
    public class UpdateDataUserModel
    {
        [Required]
        public string id_user { get; set; }

        [Required]
        [EmailAddress]
        public string email_user { get; set; }

        [Required]
        public string name_user { get; set; }

        [Required]
        public string lastname_user { get; set; }
    }
}
