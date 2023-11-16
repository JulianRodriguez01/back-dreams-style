using ApiPersons.Repositories;
using ApiPersons.Utilities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using PantAPIDreamsStyle.models.user;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

using System.Text;

namespace ApiPersons.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserRepository userRepository;

        public UserController(IUserRepository userRepository) {  
            this.userRepository = userRepository;
        }

        [HttpGet("user/")]
        public async Task<IActionResult> getListUser() {
            return Ok(await userRepository.getListUsers());
        }

        [HttpGet("user/{document_number}")]
        [ProducesResponseType(typeof(User), 200)] 
        [ProducesResponseType(typeof(string), 404)]
        public async Task<IActionResult> getUser(string document_number)
        {
            var user = await userRepository.getUser(document_number);
            return Ok(user);
        }

        [HttpGet("user/email/{email}")]
        [ProducesResponseType(typeof(User), 200)]
        [ProducesResponseType(typeof(string), 404)]
        public async Task<IActionResult> getUserEmail(string email)
        {
            var user = await userRepository.getUserEmail(email);
            return Ok(user);
        }

        [HttpPut("update-user/")]
        public async Task<IActionResult> updateUser([FromBody] User user)
        {
            if (user == null)
                return BadRequest();
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            await userRepository.updateUser(user);
            return NoContent();
        }

        [HttpDelete("remove-user/")]
        public async Task<IActionResult> deleteUser([FromBody] string document_number)
        {
            await userRepository.removeUser(new User { document_number = document_number });
            return NoContent();
        }

        [HttpPost("add-user/")]
        public async Task<IActionResult> addUser([FromBody] User user)
        {
            if (user == null)
                return BadRequest("El objeto 'user' es nulo.");

            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage);

                return BadRequest(errors);
            }
            return Created("Created", await userRepository.addUser(user));
        }

        [HttpPost("login/")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            User isAuthenticated = await userRepository.login(loginModel.Email, loginModel.Password);
            if (isAuthenticated == null)
            {
                return Unauthorized();
            }
            var tokenString = GenerateJwtToken(loginModel.Email);
            return Ok(new { token = tokenString, message = "Ingresaste con éxito a DreamsStyle." });
        }

        private string GenerateJwtToken(string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                throw new ArgumentNullException(nameof(email), "El correo electrónico no puede ser nulo o vacío. uwu");
            }
            var key = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
            new Claim(ClaimTypes.Name, email),
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);
            return tokenString;
        }

        
        [HttpPost("send-email/{email}")]
        public async Task<IActionResult> SendRecoveryEmail([FromBody] RecoveryEmailModel recoveryEmailModel)
        {
            try
            {
                var user = await userRepository.getUserRecoveryAccount(recoveryEmailModel.Email);
                if(user == null)
                {
                    return BadRequest(new { message = "Error al enviar el correo de recuperación." });
                }
                var mailHelper = new MailHelper();
                string userName = user.name_user;
                string token = TokenGenerator.generateRandomToken();
                await userRepository.setToken(recoveryEmailModel.Email, token);
                mailHelper.SendEmail(recoveryEmailModel.Email, userName, token );
                return Ok(new { message = "Correo de recuperación enviado con éxito." });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = "Error al enviar el correo de recuperación." });
            }
        }

        [HttpPost("updatePassword/{password}")]
        public async Task<IActionResult> SetNewPassword([FromBody] UpdatePasswordModel updatePasswordModel)
        {
            try
            {
                await userRepository.UpdateNewPassword(updatePasswordModel.Email, updatePasswordModel.Token, updatePasswordModel.NewPassword);
                return Ok(new { message = "Contraseña actualizada con éxito." });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = "Error al actualizar la contraseña." });
            }
        }

        /*
        [HttpPost]
        [Route("RecoverPassword")]
        public async Task<IActionResult> recoverPassword([FromBody] string email)
        {
            User user = await userRepository.getUser(email);
            if (user == null)
            {
                return BadRequest();
            }
            string myToken = await TokenGenerator.generatePasswordResetTokenAsync();
            string link = Url.Action("ResetPassword", "Account", new { token = myToken }, protocol: HttpContext.Request.Scheme);
            _mailHelper.SendMail(request.Email, "Password Recover", $"<h1>Password Recover</h1>" +
                $"Click on the following link to change your password:<p>" +
                $"<a href = \"{link}\">Change Password</a></p>");

            return Ok(new Response { IsSuccess = true });
        }
        */
    }
}
