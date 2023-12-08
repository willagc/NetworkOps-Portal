from flask import Flask, render_template, request
from netmiko import ConnectHandler

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/run_linux_command_key', methods=['POST'])
def run_linux_command_key():
    if request.method == 'POST':
        linux_device_ip = request.form['linux_device_ip']
        linux_username = request.form['linux_username']
        linux_key_file = request.form['linux_key_file']
        linux_command = request.form['linux_command']

        # Netmiko script for Linux using SSH key authentication
        linux_device = {
            'device_type': 'linux',
            'ip': linux_device_ip,
            'username': linux_username,
            'key_file': linux_key_file,
        }

        try:
            with ConnectHandler(**linux_device) as net_connect:
                linux_output = net_connect.send_command(linux_command)
        except Exception as e:
            linux_output = f"Error: {str(e)}"

        return render_template('result.html', linux_output=linux_output)

if __name__ == '__main__':
    app.run(debug=True)

