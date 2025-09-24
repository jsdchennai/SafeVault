-- Create Users table with BCrypt password storage and account lockout
CREATE TABLE Users (
    UserId INT IDENTITY(1,1) PRIMARY KEY,
    Username NVARCHAR(50) NOT NULL UNIQUE,
    PasswordHash NVARCHAR(MAX) NOT NULL,  -- BCrypt hash
    CreatedAt DATETIME2 NOT NULL,
    LastLoginAttempt DATETIME2 NULL,
    LoginAttempts INT NOT NULL DEFAULT 0,
    IsLocked BIT NOT NULL DEFAULT 0,
    LockoutEnd DATETIME2 NULL
);

-- Create index for username lookups
CREATE UNIQUE INDEX IX_Users_Username ON Users(Username);

-- Create index for monitoring locked accounts
CREATE INDEX IX_Users_Locked ON Users(IsLocked) WHERE IsLocked = 1;