using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using apiUniversidade.DTO;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

[ApiController]
    [Route("[controller]")]
    public class AutorizaController : Controller
    {
         private readonly UserManager<IdentityUser> _userManager;
         private readonly SignInManager<IdentityUser> _signInManager;
         public AutorizaController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
         {
            _userManager = userManager;
            _signInManager = signInManager;
         }

        [HttpGet]
        public ActionResult<string> Get(){
            return "AutorizaController :: Acessado em : "
                + DateTime.Now.ToLongDateString();
        }

        [HttpPost("register")]
        public async Task<ActionResult> RegisterUser([FromBody]UsuarioDTO model){
            var user = new IdentityUser{
                UserName = model.Email,
                Email = model.Email,
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if(!result.Succeeded)
                return BadRequest(result.Errors);
            
            await _signInManager.SignInAsync(user, false);
            return Ok();
        }
        
        [HttpPost("login")]
        public async Task<ActionResult> Login([FromBody] UsuarioDTO userinfo){
            var result = await _signInManager.PasswordSignInAsync(userinfo.Email, userinfo.Password, 
                    isPersistent: false, lockoutOnFailure: false);
            
            if(result.Succeeded)
                return Ok();
            else{
                ModelState.AddModelError(string.Empty,"Login inválido...");
                return BadRequest(ModelState);
            }
        }

        private UsuarioToken GeraToken(UsuarioDTO userInfo){
            var claims = new[]{
                new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                new Claim("IFRN","TecInfo"),
                new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:key"]));

            var credentials = new SigningCredentials(key,SecurityAlgorithms.HmacSha256);

            var expiracao = _configuration["TokenConfiguration:ExpireHours"];
            var expiration = DateTime.UtcNow.AddHours(double.Parse(expiracao));

            JwtSecurityToken token = new JwtSecurityToken(
                issuer: _configuration["TokenConfiguration:Issuer"],
                audience: _configuration["TokenConfiguration:Audience"],
                claims: claims,
                expires: expiration,
                signingCredentials: credentials
            );

            return new UsuarioToken(){
                Authenticated = true,
                Expiration = expiration,
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Message = "JWT Ok."
            };
        }
    }