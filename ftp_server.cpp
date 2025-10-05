#include <iostream>
#include <thread>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unordered_map>
#include <cstring> 
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

#define MAX_BUFFER_SIZE 1024
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
    }
    string getCurrentDirectory()
    {
        // relative path
        string relative = fs::relative(current_dir, home_dir).string();
        return "/" + (relative == "." ? "" : relative);
    }
    bool changeDirectory(const string &path)
    {
        fs::path target_path;
        if (path == ".." || path == "../")
        {
            // both indicates parent directory
            target_path = fs::path(current_dir).parent_path();
        }
        else if (path.empty() || path == "/")
        {
            // home directory
            target_path = home_dir;
        }
        else if (path[0] == '/')
        {
            // treat the absolute paths relative to home directory
            target_path = home_dir + path;
        }
        else
        {
            // relative path to the current directory
            target_path = fs::path(current_dir) / fs::path(path);
        } 
        try {
            // security checks

            fs::path canonical_target = fs::weakly_canonical(target_path);
            if(!fs::exists(canonical_target) || !fs::is_directory(canonical_target)) {
                return false;
            }

            string target_str = canonical_target.string(); 
            if(target_str.rfind(home_dir, 0) != 0) {
                cerr << "Directory traversal attempt blocked." << endl;
            }
        } catch(const fs::filesystem_error& e) {
            cerr << "[ERROR]: " << e.what() << endl;
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
            cerr << "[ERROR:] " << e.what() << endl;
        }
        return files;
    }
    bool makeDirectory(const string &dirname)
    {
        // some bugs
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
    bool removeDirectory(const string &dirname) {
        fs::path new_path = fs::path(current_dir) / dirname;
        if(fs::exists(new_path) && fs::is_directory(new_path)) {
            fs::remove(new_path);
            return true;
        }
        return false;
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
            string hashedPassword = user_db[username];
            return BCrypt::validatePassword(password, hashedPassword);

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

unordered_map<string, string> AuthManager::user_db;
mutex AuthManager::db_mutex;


class EventHandler
{
protected:
    int sock;
public:
    EventHandler(int socketId) : sock(socketId){}
    virtual void handler() = 0;
};

class ClientHandler : public EventHandler
{
public:
    ClientHandler(int socketId) : EventHandler(socketId) {}
    void handler() override
    {
        int client = this->sock;
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
                if (authenticated)
                {
                    response = "230 Already logged in.\r\n";
                }
                else if (AuthManager::user_exits(argument))
                {
                    current_user = argument;
                    response = "331 Username OK, need password\r\n";
                }
                else
                {
                    response = "530 Not logged in\r\n";
                }
            }
            else if (command_type == "PASS")
            {
                if (current_user.empty())
                {
                    response = "503 Bad sequence of commands\r\n";
                }
                else if (AuthManager::validate_user(current_user, argument))
                {
                    authenticated = true;
                    shell = make_unique<FTPShell>("./" + current_user);
                    response = "230 User logged in\r\n";
                }
                else
                {
                    response = "530 Not logged in\r\n";
                    current_user = "";
                }
            }
            else if (command_type == "PASS")
            {
                response = "230 User logged in\r\n";
            }
            else if (command_type == "QUIT")
            {
                response = "221 Goodbye\r\n";
                send(client, response.c_str(), response.length(), 0);
                cout << "Client disconnected" << endl;
                close(client);
                break;
            }
            else if (authenticated)
            {

                if (command_type == "PWD")
                {
                    response = "257 \"" + shell->getCurrentDirectory() + "\" is the current directory.\r\n";
                }
                else if (command_type == "CWD")
                {
                    if (shell->changeDirectory(argument))
                    {
                        response = "250 Directory successfully changed.\r\n";
                    }
                    else
                    {
                        response = "550 Failed to change directory.\r\n";
                    }
                }
                else if (command_type == "CDUP")
                {
                    if (shell->changeDirectory(".."))
                    {
                        response = "200 Directory successfully changed.\r\n";
                    }
                    else
                    {
                        response = "550 Failed to change directory.\r\n";
                    }
                }
                else if (command_type == "MKD")
                {
                    if (shell->makeDirectory(argument))
                    {
                        response = "257 Directory created.\r\n";
                    }
                    else
                    {
                        response = "550 Failed to create directory. \r\n";
                    }
                }
                else if (command_type == "LIST")
                {
                    vector<string> files = shell->listFiles();
                    stringstream ss;
                    ss << "226 List follows (" << files.size() << " items):\r\n";
                    for (const auto &file : files)
                    {
                        ss << file << "\r\n";
                    }
                    ss << "226 Transfer complete.\r\n";
                    response = ss.str();
                } else if(command_type == "RMD") {
                    if(shell->removeDirectory(argument)) {
                        response = "250 Directory removed.\r\n";
                    } else {
                        response = "550 Failed to remove directory.\r\n";
                    }
                }
            }
            else
            {
                response = "502 Command not implemented.\r\n";
            }
            send(client, response.c_str(), response.length(), 0);
        }
    }
};

void client_thread_function(unique_ptr<ClientHandler> client_handler) {
    client_handler->handler();
}

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
        auto client_handler_ptr = make_unique<ClientHandler>(clientfd);
        thread client_thread(client_thread_function, move(client_handler_ptr));
        client_thread.detach();
    }
};

int main()
{
    if (!AuthManager::user_exits("admin"))
    {
        AuthManager::add_user("admin", "admin123");
        AuthManager::add_user("user", "1234");
    }

    SocketServer server(2121);
    server.setup();
    cout << "FTP Server running at PORT 2121" << endl;
    while (true)
    {
        server.accept_connection();
    }
    
}
