FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app
COPY . .
RUN dotnet restore
RUN dotnet publish "SIEM.Scanner/SIEM.Scanner.csproj" -c Release -o /out

FROM mcr.microsoft.com/dotnet/runtime:8.0
WORKDIR /app
COPY --from=build /out .
COPY SIEM.Scanner/server.pfx . 
ENTRYPOINT ["dotnet", "SIEM.Scanner.dll"]