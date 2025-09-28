#include <iostream>
#include <thread>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unordered_map>
#include <cstring> // memset
#include <unistd.h>
#include <mutex>
#include <arpa/inet.h>
#include <unistd.h>
#include <bcrypt/BCrypt.hpp>
#include <fstream>
#include <filesystem>
#include <vector>
#include <memory>
#include <utility>
#include <algorithm>
using namespace std;
namespace fs = std::filesystem;
class FTPShell
{
private:
    string home_dir;
    string current_dir;

public:
    FTPShell(string directory) : home_dir(directory)
    {
        if (!fs::exists(home_dir))
        {
            fs::create_directory(home_dir);
        }
        current_dir = home_dir;
        fs::current_path(home_dir);
    }
    string getCurrentDirectory()
    {
        // relative path
        string relative = fs::relative(fs::current_path(), home_dir).string();
        return "/" + (relative == "." ? "" : relative);
    }
    bool changeDirectory(const string &path)
    {
        fs::path target_path;
        if (path == ".." || path == "../")
        {
            target_path = fs::path(current_dir).parent_path();
        }
        else if (path.empty() || path == "/")
        {
            target_path = home_dir;
        }
        else if (path[0] == '/')
        {
            target_path = fs::path(home_dir) / fs::path(path).relative_path();
        }
        else
        {
            target_path = fs::path(current_dir) / fs::path(path);
        }

        if (target_path.empty() || !fs::exists(target_path) || !fs::is_directory(target_path) || target_path.string().find(home_dir) == 0)
        {
            return false;
        }
        current_dir = target_path.string();
        return true;
    }
    vector<string> listFiles()
    {
        vector<string> files;
        try
        {
            for (const auto &entry : fs::directory_iterator(fs::current_path()))
            {
                files.push_back(entry.path().filename().string());
            }
        }
        catch (fs::filesystem_error &e)
        {
            cerr << "ERROR: " << e.what() << endl;
        }
        return files;
    }
    bool makeDirectory(const string &dirname)
    {
        fs::path new_dir = fs::path(current_dir) / dirname;
        try
        {
            if (fs::exists(new_dir))
            {
                return false;
            }
            return fs::create_directory(new_dir);
        }
        catch (fs::filesystem_error &e)
        {
            cerr << "ERROR: " << e.what() << endl;
            return false;
        }
    }
};
class AuthManager
{
private:
    static unordered_map<string, string> user_db;
    static mutex db_mutex;

public:
    AuthManager()
    {
        ifstream infile("users.auth");
        if (!infile.is_open())
        {
            cerr << "Could not open user database file." << endl;
            return;
        }
        string line;
        string username, password_hash;
        while (getline(infile, line))
        {
            if (line.empty())
                continue;
            size_t delimiter_pos = line.find(':');
            if (delimiter_pos == string::npos)
            {
                cerr << "WARNING: corrupted user file" << endl;
                continue;
            }
            username = line.substr(0, delimiter_pos);
            password_hash = line.substr(delimiter_pos + 1);
            user_db[username] = password_hash;
        }
        infile.close();
        cout << "Successfully loaded user database." << endl;
    }
    static bool user_exits(const string &username)
    {
        return user_db.find(username) != user_db.end();
    }
    static bool validate_user(const string &username, const string &password)
    {
        if (user_exits(username))
        {
            return user_db[username] == password;
        }
        return false;
    }
    static bool add_user(const string &username, const string &password)
    {
        lock_guard<mutex> lock(db_mutex);
        if (user_exits(username))
        {
            return false;
        }
        string new_password_hash = BCrypt::generateHash(password);
        user_db[username] = new_password_hash;
        return true;
    }
    ~AuthManager()
    {
        ofstream outfile("users.auth");
        if (!outfile.is_open())
        {
            cerr << "ERROR: Could not open user database file for writing." << endl;
            return;
        }
        for (const auto &pair : user_db)
        {
            outfile << pair.first << ":" << pair.second << endl;
        }
        outfile.close();
        cout << "User database saved successfully" << endl;
    }
};
class ThreadSpawner
{
private:
    thread t;

public:
    template <typename F, typename... TArgs>
    ThreadSpawner(F &&operation, TArgs &&...args)
    {
        t = thread(forward<F> operation, forward<TArgs>(args)...);
    }
    ~ThreadSpawner()
    {
        if (t.joinable())
        {
            t.join();
        }
    }
    void detach()
    {
        if (t.joinable())
        {
            t.detach();
        }
    }
    void join()
    {
        if (t.joinable())
        {
            t.join();
        }
    }
};

class EventHandler
{
public:
    virtual void handler(int sock) = 0;
};

class ClientHandler : public EventHandler
{
public:
    void handler(int client) override
    {
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        string welcome_msg = "220 Welcome to the FTP server\r\n";
        send(client, welcome_msg.c_str(), welcome_msg.length(), 0);
        bool authenticated = false;
        string current_user = "";

        unique_ptr<FTPShell> shell = nullptr;
        while (true)
        {
            memset(buffer, 0, sizeof(buffer));
            int bytes_received = recv(client, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received <= 0)
            {
                cout << "Client disconnected" << endl;
                close(client);
                break;
            }
            buffer[bytes_received] = '\0';
            string command(buffer);
            cout << "Received command: " << command;
            string response = "200 OK\r\n";

            string command_type = command.substr(0, command.find(' '));
            string argument = command.find(' ') != string::npos ? command.substr(command.find(' ') + 1) : "";

            transform(command_type.begin(), command_type.end(), command_type.begin(), ::toupper);

            if (command_type == "USER")
            {
                if(authenticated) {
                    response = "230 Already logged in.\r\n";
                } else if(AuthManager::user_exists(argument)) {
                    current_user = argument;
                    response = "331 Username OK, need password\r\n";
                } else {
                    response = "530 Not logged in\r\n";
                }
            } else if(command_type == "PASS") {
                if(current_user.empty()) {
                    response = "503 Bad sequence of commands\r\n";
                } else if(AuthManager::validate_user(current_user, argument)) {
                    authenticated = true;
                    shell = make_unique<FTPShell>("./" + current_user);
                    response = "230 User logged in\r\n";
                } else {
                    response = "530 Not logged in\r\n";
                    current_user = "";
                }
            }
            else if (command.substr(0, 4) == "PASS")
            {
                response = "230 User logged in\r\n";
            }
            else if (command.substr(0, 4) == "QUIT")
            {
                response = "221 Goodbye\r\n";
                send(client, response.c_str(), response.length(), 0);
                cout << "Client disconnected" << endl;
                close(client);
                break;
            }
            send(client, response.c_str(), response.length(), 0);
        }
    }
};
class SocketServer
{
private:
    int sockfd = -1;
    int clientfd = -1;
    struct sockaddr_in servaddr, cli;
    int port;
    int *client_sock_ptr = new int;

public:
    SocketServer(int port)
    {
        this->port = port;
    }
    void setup()
    {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0)
        {
            cerr << "ERROR creating socket" << endl;
            return;
        }
        memset(&servaddr, 0, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_port = htons(port);
        if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        {
            cerr << "ERROR on binding" << endl;
            return;
        }

        if (listen(sockfd, 5) < 0)
        {
            cerr << "ERROR on listening" << endl;
            return;
        }
    }
    void accept_connection()
    {

        socklen_t len = sizeof(cli);
        clientfd = accept(sockfd, (struct sockaddr *)&cli, &len);
        if (clientfd < 0)
        {
            cerr << "ERROR on accept" << endl;
            return;
        }
        cout << "Client connected" << endl;
        ClientHandler client;

        // ThreadSpawner t1(client.handler(), clientfd); 
        t1.detach();
    }
};

int main() {
    if(!AuthManager::user_exits("admin")) {
        AuthManager::add_user("admin", "admin123");
    }
}
