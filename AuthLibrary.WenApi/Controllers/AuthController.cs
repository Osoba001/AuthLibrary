using Auth.UserServices;
using AuthLibrary.WenApi.DTO;
using Microsoft.AspNetCore.Mvc;

namespace AuthLibrary.WenApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IUserRoleService _userRoleService;

        public AuthController(IUserService userService,IUserRoleService userRoleService)
        {
            _userService = userService;
            _userRoleService = userRoleService;
        }

        [HttpPost]
        public async Task<IActionResult> RegisterUser([FromBody] CreateUserCommand user)
        {
            var resp = await _userService.Register(user.Email, user.Name, user.Password);
            if (resp.IsSuccess && resp.Entity!.RefreshToken != null)
            {
                Response.Cookies.Append("refreshToken", resp.Entity.RefreshToken, new CookieOptions { HttpOnly = true });
                return Ok(resp.Entity.AccessToken);
            }
            return BadRequest(resp.FistError);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginCommand login)
        {
            var resp = await _userService.Login(login.Email, login.Password);
            if (resp.IsSuccess && resp.Entity!.RefreshToken!=null)
            {
                Response.Cookies.Append("refreshToken",resp.Entity.RefreshToken, new CookieOptions { HttpOnly= true });
                return Ok(resp.Entity.AccessToken);
            }
            return BadRequest(resp.FistError);
        }

        [HttpGet("all-users")]
        public async Task<IActionResult> GetAllUsers()
        {
            return Ok(await _userService.AllUsers());
        }

        [HttpGet("False-deleted-users")]
        public async Task<IActionResult> GetFalseDeletedUsers()
        {
            return Ok(await _userService.GetFalseDeletedUsers());
        }

        [HttpPost("user-role")]
        public async Task<IActionResult> AddRole(string userRole)
        {
            var resp=await _userRoleService.AddRole(userRole);
            if (resp.IsSuccess)
                return Ok();
            return BadRequest(resp.FistError);
        }

        [HttpGet("user-roles")]
        public async Task<IActionResult> GetAllRoles()
        {
            return Ok(await _userRoleService.GetAllRoles());
        }

        [HttpGet("refresh-accessToken")]
        public async Task<IActionResult> ResfreshAccessToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if (refreshToken!=null)
            {
                var res = await _userService.RefreshToken(refreshToken);
                if (res.IsSuccess)
                    return Ok(res.Entity!.AccessToken);
                else
                    return BadRequest(res.FistError);
            }else
                return BadRequest("Refresh to is null.");
        }

        [HttpDelete]
        public async Task<IActionResult> FalseDeleteUser(Guid userId)
        {
            var res=await _userService.FalseDeleteUser(userId);
            if (res.IsSuccess)
                return Ok();
            else
                return BadRequest(res.FistError);
        }

        [HttpPut("Undo-False-delete")]
        public async Task<IActionResult> UndoFalseDelete(Guid userId)
        {
            var res = await _userService.UndoFalseDelete(userId);
            if (res.IsSuccess)
                return Ok();
            else
                return BadRequest(res.FistError);
        }

        [HttpDelete("hard-delete")]
        public async Task<IActionResult> HardDeleteUser(Guid userId)
        {
            var res = await _userService.HardDeleteUser(userId);
            if (res.IsSuccess)
                return Ok();
            else
                return BadRequest(res.FistError);
        }

        [HttpGet("User-by-role")]
        public async Task<IActionResult> GetUserByRole(string role)
        {
            return Ok(await _userService.UsersByRoles(role));
        }

        [HttpPut("add-role-to-user")]
        public async Task<IActionResult> AddRoleToUser(Guid userId ,string role)
        {
            var res=await _userService.AddRoleToUser(userId,role);
            if (res.IsSuccess)
                return Ok();
            else
                return BadRequest(res.FistError);
        }
        [HttpPut("remove-role-from-user")]
        public async Task<IActionResult> RemoveRoleFromUser(Guid userId, string role)
        {
            var res = await _userService.RemoveRoleFromUser(userId, role);
            if (res.IsSuccess)
                return Ok();
            else
                return BadRequest(res.FistError);
        }

        [HttpPut("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordCommand changePassword)
        {
            var res=await _userService.ChangePassword(changePassword.UserId,changePassword.OldPassword,changePassword.NewPassword);  
            if (res.IsSuccess)
                return Ok();
            else
                return BadRequest(res.FistError);
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgottonPassword(string email)
        {
            var pin=await _userService.ForgottenPassword(email);
            if (pin > 0)
            {
                //send pin to the user email.
                // for testing purpose i will return pin
                return Ok(pin);
            }
            else
                return BadRequest("Invalid email");
        }

        [HttpPost("confirm-password-recovery-pin")]
        public async Task<IActionResult> PasswordRecovery([FromBody] ConfirmPinCommand confirmPin)
        {
            var res= await _userService.RecoverPassword(confirmPin.Email, confirmPin.RecoveryPin);
            if (res.IsSuccess)
                return Ok();
            else 
                return BadRequest(res.FistError);
        }

        [HttpPut("new-password")]
        public async Task<IActionResult> EnterNewPassword([FromBody] NewPasswordCommand newPassword)
        {
            var res = await _userService.NewPassword(newPassword.Password, newPassword.Email, newPassword.RecoveryPin);
            if (res.IsSuccess)
                return Ok();
            else
                return BadRequest(res.FistError);
        }
    }
}
