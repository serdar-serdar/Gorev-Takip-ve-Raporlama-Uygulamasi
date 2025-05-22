# Gorev-Takip-ve-Raporlama-Uygulamasi
Staj danismani tarafından verilen gorevle ilgili yapılanlar.

-------------------------------------------
AppDataContext.cs

using Microsoft.EntityFrameworkCore;
using GorevTakipAPI.Models;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<User> Users { get; set; }
    public DbSet<TaskItem> Tasks { get; set; }
}

---------------------------------

AppSettings

"ConnectionStrings": {
  "DefaultConnection": "Server=localhost;Database=GorevTakipDB;Trusted_Connection=True;"
},
"Jwt": {
  "Key": "your-super-secret-key",
  "Issuer": "GorevTakipAPI",
  "Audience": "GorevTakipClient"
}

---------------------------------

AppController.cs

using Microsoft.AspNetCore.Mvc;
using GorevTakipAPI.Models;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AuthService _authService;

    public AuthController(AuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(UserRegisterDto dto)
    {
        var result = await _authService.Register(dto);
        if (!result) return BadRequest("Username already exists.");
        return Ok("User registered successfully.");
    }

    [HttpPost("login")]
    public async Task<ActionResult<AuthResponseDto>> Login(UserLoginDto dto)
    {
        var token = await _authService.Login(dto);
        if (token == null) return Unauthorized("Invalid credentials.");
        return Ok(new AuthResponseDto { Token = token });
    }
}

-----------------------------------

AppResponseDto.cs

public class AuthResponseDto
{
    public string Token { get; set; }
}

--------------------------------------------------------

AppService.cs

builder.Services.AddScoped<AuthService>();

------------------------------------------------------

Görev Takip API

dotnet new webapi -n GorevTakipAPI
cd GorevTakipAPI

------------------------------------------------------

builder.cs

builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();
builder.Services.AddScoped<ITaskRepository, TaskRepository>();

-------------------------------------------------------

builder.Service.cs

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!))
        };
    });

-------------------------------------------------------------

Core Web API

dotnet new webapi -n GorevTakipAPI
cd GorevTakipAPI

----------------------------------------------------------

GorevTakipAPI.cs

using GorevTakipAPI.Models;

public interface ITaskRepository
{
    Task<List<TaskItem>> GetAllByUserAsync(int userId);
    Task<TaskItem?> GetByIdAsync(int id, int userId);
    Task AddAsync(TaskItem task);
    void Update(TaskItem task);
    void Delete(TaskItem task);
}

-------------------------------------------------------

GorevTakipAPI01.cs

using GorevTakipAPI.Models;
using Microsoft.EntityFrameworkCore;

public class TaskRepository : ITaskRepository
{
    private readonly AppDbContext _context;

    public TaskRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task<List<TaskItem>> GetAllByUserAsync(int userId)
    {
        return await _context.Tasks.Where(t => t.UserId == userId).ToListAsync();
    }

    public async Task<TaskItem?> GetByIdAsync(int id, int userId)
    {
        return await _context.Tasks.FirstOrDefaultAsync(t => t.Id == id && t.UserId == userId);
    }

    public async Task AddAsync(TaskItem task)
    {
        await _context.Tasks.AddAsync(task);
    }

    public void Update(TaskItem task)
    {
        _context.Tasks.Update(task);
    }

    public void Delete(TaskItem task)
    {
        _context.Tasks.Remove(task);
    }
}

--------------------------------------------

GorevTakipAPI.cs

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using GorevTakipAPI.Models;
using System.Security.Claims;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class TaskController : ControllerBase
{
    private readonly IUnitOfWork _unitOfWork;

    public TaskController(IUnitOfWork unitOfWork)
    {
        _unitOfWork = unitOfWork;
    }

    private int GetUserId() => int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var tasks = await _unitOfWork.Tasks.GetAllByUserAsync(GetUserId());
        return Ok(tasks);
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> Get(int id)
    {
        var task = await _unitOfWork.Tasks.GetByIdAsync(id, GetUserId());
        if (task == null) return NotFound();
        return Ok(task);
    }

    [HttpPost]
    public async Task<IActionResult> Create(TaskDto dto)
    {
        var task = new TaskItem
        {
            Title = dto.Title,
            Description = dto.Description,
            StartDate = dto.StartDate,
            EndDate = dto.EndDate,
            Priority = dto.Priority,
            IsCompleted = false,
            UserId = GetUserId()
        };

        await _unitOfWork.Tasks.AddAsync(task);
        await _unitOfWork.CompleteAsync();

        return Ok(task);
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(int id, TaskDto dto)
    {
        var task = await _unitOfWork.Tasks.GetByIdAsync(id, GetUserId());
        if (task == null) return NotFound();

        task.Title = dto.Title;
        task.Description = dto.Description;
        task.StartDate = dto.StartDate;
        task.EndDate = dto.EndDate;
        task.Priority = dto.Priority;

        _unitOfWork.Tasks.Update(task);
        await _unitOfWork.CompleteAsync();

        return Ok(task);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(int id)
    {
        var task = await _unitOfWork.Tasks.GetByIdAsync(id, GetUserId());
        if (task == null) return NotFound();

        _unitOfWork.Tasks.Delete(task);
        await _unitOfWork.CompleteAsync();

        return NoContent();
    }

    [HttpPost("{id}/complete")]
    public async Task<IActionResult> MarkAsComplete(int id)
    {
        var task = await _unitOfWork.Tasks.GetByIdAsync(id, GetUserId());
        if (task == null) return NotFound();

        task.IsCompleted = true;
        _unitOfWork.Tasks.Update(task);
        await _unitOfWork.CompleteAsync();

        return Ok(task);
    }
}

-------------------------------------------------

InıtıalCreate.cs

dotnet ef migrations add InitialCreate
dotnet ef database update

------------------------------------------------

IUnitOfWork.cs

public interface IUnitOfWork
{
    ITaskRepository Tasks { get; }
    Task<int> CompleteAsync();
}

---------------------------------------------------

NuGet Packages

dotnet add package Microsoft.EntityFrameworkCore.SqlServer
dotnet add package Microsoft.EntityFrameworkCore.Tools
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package System.IdentityModel.Tokens.Jwt
dotnet add package BCrypt.Net-Next

-----------------------------------------------------

Program.cs

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Configure token validation here
    });

builder.Services.AddAuthorization();
builder.Services.AddControllers();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

----------------------------------------------

System.IdentityModel.Tokens.cs

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using BCrypt.Net;
using GorevTakipAPI.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

public class AuthService
{
    private readonly AppDbContext _context;
    private readonly IConfiguration _config;

    public AuthService(AppDbContext context, IConfiguration config)
    {
        _context = context;
        _config = config;
    }

    public async Task<bool> Register(UserRegisterDto dto)
    {
        if (await _context.Users.AnyAsync(u => u.Username == dto.Username)) return false;

        var user = new User
        {
            Username = dto.Username,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.Password)
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        return true;
    }

    public async Task<string?> Login(UserLoginDto dto)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == dto.Username);
        if (user == null || !BCrypt.Net.BCrypt.Verify(dto.Password, user.PasswordHash))
            return null;

        return GenerateJwtToken(user);
    }

    private string GenerateJwtToken(User user)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username)
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

--------------------------------------------------------

public class TaskDto
{
    public string Title { get; set; }
    public string? Description { get; set; }
    public DateTime StartDate { get; set; }
    public DateTime EndDate { get; set; }
    public string Priority { get; set; }
}

---------------------------------------------------------

TaskItem.cs

public class TaskItem
{
    public int Id { get; set; }
    public string Title { get; set; }
    public string Description { get; set; }
    public DateTime StartDate { get; set; }
    public DateTime EndDate { get; set; }
    public string Priority { get; set; }
    public bool IsCompleted { get; set; }

    public int UserId { get; set; }
    public User User { get; set; }
}

--------------------------------------------------------

User.cs

public class User
{
    public int Id { get; set; }
    public string Username { get; set; }
    public string PasswordHash { get; set; }

    public ICollection<TaskItem> Tasks { get; set; }
}

-------------------------------------------------------

UserLoginDto.cs

public class UserLoginDto
{
    public string Username { get; set; }
    public string Password { get; set; }
}

-------------------------------------------------------

UserRegisterDto.cs

public class UserRegisterDto
{
    public string Username { get; set; }
    public string Password { get; set; }
}

--------------------------------------------------------
