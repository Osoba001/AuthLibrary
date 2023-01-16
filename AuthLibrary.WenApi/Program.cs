using static Auth.AuthConfigurations.AuthConfigurationService;
using Auth.Data;
using Auth.Models;
using Auth.AuthConfigurations;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddCors(opt =>
{
    opt.AddDefaultPolicy(x =>
    {
        x
        .WithOrigins(builder.Configuration.GetSection("AllowedOrigins").Get<string[]>())
        //.WithHeaders("Authorization")
        .AllowAnyHeader()
        .WithMethods("GET", "POST", "PUT", "PATCH", "DELETE");
    });
});
var config = builder.Configuration;
builder.Services.AddSqlServer<AuthDbContext>(config.GetSection("AuthConfigModel:ConnString").Value!, op =>
{
    op.EnableRetryOnFailure().CommandTimeout(60).MaxBatchSize(2);
});
builder.Services.Configure<AuthConfigModel>(config.GetSection(nameof(AuthConfigModel)));
builder.Services.AuthConfigService(config.GetSection("AuthConfigModel:SecretKey").Value!);
builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseCors();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
