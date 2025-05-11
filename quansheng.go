package quansheng_uvk5

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"go.bug.st/serial" // Using go.bug.st/serial for cross-platform serial port access
)

// Constants based on the documentation
const (
	baudRate         = 38400
	dataBits         = 8
	parity           = serial.NoParity
	stopBits         = serial.OneStopBit
	readTimeout      = 2 * time.Second // Timeout for serial read operations
	responseWaitTime = 500 * time.Millisecond // Time to wait for a response after sending a command
)

var (
	packetHeader = []byte{0xAB, 0xCD}
	packetFooter = []byte{0xDC, 0xBA}
	xorKey       = []byte{
		0x16, 0x6C, 0x14, 0xE6, 0x2E, 0x91, 0x0D, 0x40,
		0x21, 0x35, 0xD5, 0x40, 0x13, 0x03, 0xE9, 0x80,
	}
)

// Radio struct holds the connection and configuration for the UV-K5 radio
type Radio struct {
	port     serial.Port
	portName string
	Debug    bool // Enable debug logging
}

// NewRadio creates a new Radio instance but does not connect yet.
func NewRadio(portName string) *Radio {
	return &Radio{
		portName: portName,
		Debug:    false,
	}
}

// Connect establishes a serial connection to the radio.
func (r *Radio) Connect() error {
	mode := &serial.Mode{
		BaudRate: baudRate,
		DataBits: dataBits,
		Parity:   parity,
		StopBits: stopBits,
	}

	if r.Debug {
		fmt.Printf("Attempting to open port %s with baud %d\n", r.portName, baudRate)
	}

	port, err := serial.Open(r.portName, mode)
	if err != nil {
		return fmt.Errorf("failed to open serial port %s: %w", r.portName, err)
	}
	r.port = port

	// Set a timeout for read operations
	if err := r.port.SetReadTimeout(readTimeout); err != nil {
		r.port.Close() // Close port if setting timeout fails
		return fmt.Errorf("failed to set read timeout: %w", err)
	}

	if r.Debug {
		fmt.Printf("Successfully connected to %s\n", r.portName)
	}
	return nil
}

// Disconnect closes the serial connection.
func (r *Radio) Disconnect() error {
	if r.port != nil {
		if r.Debug {
			fmt.Printf("Disconnecting from %s\n", r.portName)
		}
		return r.port.Close()
	}
	return nil
}

// calculateCRC16XMODEM calculates the CRC-16/XMODEM checksum for the given data.
// Polynomial: 0x1021, Initial Value: 0x0000
func calculateCRC16XMODEM(data []byte) uint16 {
	var crc uint16 = 0x0000
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if (crc & 0x8000) != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// xorObfuscate applies XOR obfuscation/de-obfuscation to the data.
func xorObfuscate(data []byte) []byte {
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ xorKey[i%len(xorKey)]
	}
	return result
}

// buildCommandPacket constructs a command packet to be sent to the radio.
// DATA is the actual command and its parameters, without CRC.
func buildCommandPacket(data []byte) ([]byte, error) {
	if len(data) == 0 {
		// Some commands might be very short, e.g., a single byte for version request
		// For now, let's assume data is not empty unless explicitly handled by the caller
	}

	// 1. Calculate CRC16 of DATA
	crc := calculateCRC16XMODEM(data)
	crcBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(crcBytes, crc) // Low byte first

	// 2. Form PAYLOAD_TO_OBFUSCATE = DATA + CRC16
	payloadToObfuscate := append(data, crcBytes...)

	// 3. Get LENGTH_BYTE (length of original, unobfuscated DATA + CRC16)
	lengthByte := byte(len(payloadToObfuscate))

	// 4. XOR OBFUSCATE PAYLOAD_TO_OBFUSCATE
	obfuscatedPayload := xorObfuscate(payloadToObfuscate)

	// 5. Construct the full packet
	// <HEADER><LENGTH_BYTE><NULL_BYTE><OBFUSCATED_PAYLOAD><FOOTER>
	var packet bytes.Buffer
	packet.Write(packetHeader)
	packet.WriteByte(lengthByte)
	packet.WriteByte(0x00) // NULL_BYTE
	packet.Write(obfuscatedPayload)
	packet.Write(packetFooter)

	return packet.Bytes(), nil
}

// sendRawCommand sends a raw byte slice to the radio.
func (r *Radio) sendRawCommand(command []byte) error {
	if r.port == nil {
		return errors.New("radio not connected")
	}
	if r.Debug {
		fmt.Printf("Sending raw command: %X\n", command)
	}
	_, err := r.port.Write(command)
	if err != nil {
		return fmt.Errorf("failed to write to serial port: %w", err)
	}
	return nil
}

// readResponse attempts to read and parse a response packet from the radio.
func (r *Radio) readResponse() ([]byte, error) {
	if r.port == nil {
		return nil, errors.New("radio not connected")
	}

	reader := bufio.NewReader(r.port)
	var rawResponse bytes.Buffer
	
	// Read until footer or timeout
	// This is a simplified approach; a more robust solution might involve
	// reading byte by byte and looking for the header first.
	
	startTime := time.Now()
	buffer := make([]byte, 256) // Max expected packet size + buffer

	for {
		if time.Since(startTime) > readTimeout {
			if r.Debug && rawResponse.Len() > 0 {
				fmt.Printf("Read timeout, partial data: %X\n", rawResponse.Bytes())
			}
			return nil, errors.New("read timeout while waiting for response")
		}

		n, err := reader.Read(buffer)
		if err != nil {
			if err == io.EOF { // EOF can happen if the port is closed or timeout is very short
				if r.Debug {
					fmt.Println("EOF received while reading response")
				}
				// Continue trying to read if some data was already received, otherwise error
				if rawResponse.Len() > 0 && bytes.Contains(rawResponse.Bytes(), packetFooter) {
					break
				}
				return nil, fmt.Errorf("EOF while reading response, potentially disconnected: %w", err)
			}
			// For other errors, like serial.ErrTimeout, it's handled by the outer loop.
			// If it's a genuine error, return it.
			if !errors.Is(err, serial.ErrTimeout) { // go.bug.st/serial uses serial.ErrTimeout
				return nil, fmt.Errorf("error reading from serial port: %w", err)
			}
		}

		if n > 0 {
			rawResponse.Write(buffer[:n])
			if r.Debug {
				fmt.Printf("Read %d bytes: %X\n", n, buffer[:n])
				fmt.Printf("Current rawResponse buffer: %X\n", rawResponse.Bytes())
			}
			// Check if we have a complete packet (simplified check for header and footer)
			// A more robust parser would handle streaming data and packet framing better.
			if bytes.HasPrefix(rawResponse.Bytes(), packetHeader) && bytes.HasSuffix(rawResponse.Bytes(), packetFooter) {
				if rawResponse.Len() >= 7 { // Minimum packet size: AB CD LEN 00 PAYLOAD(min 1) DC BA
					break
				}
			}
		}
		// If no data read and not a timeout, yield briefly to avoid busy-waiting
		if n == 0 && !errors.Is(err, serial.ErrTimeout) {
			time.Sleep(10 * time.Millisecond)
		}
	}


	if r.Debug {
		fmt.Printf("Received raw response: %X\n", rawResponse.Bytes())
	}

	// Basic validation of the packet structure
	respBytes := rawResponse.Bytes()
	if len(respBytes) < 7 { // Header(2) + Length(1) + Null(1) + MinPayload(1) + Footer(2)
		return nil, fmt.Errorf("response packet too short: %d bytes, content: %X", len(respBytes), respBytes)
	}
	if !bytes.Equal(respBytes[:2], packetHeader) {
		return nil, fmt.Errorf("invalid response header: expected %X, got %X", packetHeader, respBytes[:2])
	}
	if !bytes.Equal(respBytes[len(respBytes)-2:], packetFooter) {
		// The doc mentions "footer in responses might be slightly different or less strictly checked"
		// For now, we'll be strict. If issues arise, this check can be relaxed.
		// Also, "sometimes with the last two bytes of the obfuscated payload also being 0xDC 0xBA"
		// This implies the actual footer might be part of the obfuscated data in some cases,
		// which complicates parsing significantly. Assuming standard footer for now.
		fmt.Printf("Warning: Invalid response footer: expected %X, got %X. Proceeding with parsing.\n", packetFooter, respBytes[len(respBytes)-2:])
		// return nil, fmt.Errorf("invalid response footer: expected %X, got %X", packetFooter, respBytes[len(respBytes)-2:])
	}

	// Extract fields
	// <HEADER><LENGTH_BYTE><NULL_BYTE><OBFUSCATED_RESPONSE_DATA><FOOTER>
	// Length byte specifies the length of the OBFUSCATED_RESPONSE_DATA
	obfuscatedDataLength := int(respBytes[2])
	nullByte := respBytes[3]

	if nullByte != 0x00 {
		return nil, fmt.Errorf("invalid null byte in response: expected 0x00, got 0x%02X", nullByte)
	}

	// Check if the packet length matches the actual data received
	// Expected total length = Header(2) + LenByte(1) + NullByte(1) + ObfuscatedData(obfuscatedDataLength) + Footer(2)
	expectedTotalLength := 2 + 1 + 1 + obfuscatedDataLength + 2
	if len(respBytes) != expectedTotalLength {
		// This can happen if the footer is part of the obfuscated data, or if there's trailing data.
		// The doc says "LENGTH_BYTE: (1 byte) Specifies the length of the obfuscated response data."
		// So, the obfuscated data should be from index 4 up to 4 + obfuscatedDataLength.
		if r.Debug {
			fmt.Printf("Warning: Response length mismatch. Expected total %d based on length byte, got %d. Assuming length byte is correct for obfuscated data.\n", expectedTotalLength, len(respBytes))
		}
		if 4+obfuscatedDataLength > len(respBytes)-2 { // Ensure we don't read past the footer
			return nil, fmt.Errorf("obfuscated data length (%d) exceeds available packet data (len %d before footer)", obfuscatedDataLength, len(respBytes)-2)
		}
	}
	
	obfuscatedResponseData := respBytes[4 : 4+obfuscatedDataLength]

	// De-obfuscate the response data
	deobfuscatedData := xorObfuscate(obfuscatedResponseData)

	if r.Debug {
		fmt.Printf("Deobfuscated response data: %X\n", deobfuscatedData)
	}

	return deobfuscatedData, nil
}

// SendCommandAndGetResponse sends a command (specified by its core data, without CRC)
// and waits for a response.
func (r *Radio) SendCommandAndGetResponse(commandData []byte) ([]byte, error) {
	packet, err := buildCommandPacket(commandData)
	if err != nil {
		return nil, fmt.Errorf("failed to build command packet: %w", err)
	}

	err = r.sendRawCommand(packet)
	if err != nil {
		return nil, fmt.Errorf("failed to send command: %w", err)
	}

	// Wait a short period for the radio to process and respond
	// This might need adjustment based on radio behavior.
	time.Sleep(responseWaitTime)

	response, err := r.readResponse()
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return response, nil
}

// GetFirmwareVersion attempts to read the radio's firmware version.
// Based on CHIRP: _send_command(radio, b"\x05") might be an initial handshake or version request.
// The response b"\x05QS-K520123" indicates a Quansheng UV-K5 with firmware 2.01.23.
func (r *Radio) GetFirmwareVersion() (string, error) {
	// The command data for firmware version is typically a single byte 0x05.
	commandData := []byte{0x05}

	if r.Debug {
		fmt.Println("Attempting to get firmware version...")
	}

	response, err := r.SendCommandAndGetResponse(commandData)
	if err != nil {
		return "", fmt.Errorf("failed to get firmware version: %w", err)
	}

	// The response format is: first byte is 0x05, followed by ASCII string.
	if len(response) == 0 {
		return "", errors.New("empty response for firmware version")
	}
	
	if response[0] != 0x05 {
		return "", fmt.Errorf("invalid firmware version response prefix: expected 0x05, got 0x%02X. Full response: %X", response[0], response)
	}

	if len(response) < 2 {
		return "", fmt.Errorf("firmware version response too short after prefix. Full response: %X", response)
	}

	firmwareString := string(response[1:])
	if r.Debug {
		fmt.Printf("Successfully retrieved firmware version: %s\n", firmwareString)
	}
	return firmwareString, nil
}

// ReadEEPROM sends a command to read N bytes from a given EEPROM address.
// NOTE: The exact command byte(s) for "COMMAND_BYTE_READ_EEPROM" and the format
// of ADDRESS_BYTES and LENGTH_BYTE within the command's DATA section are not
// fully specified in the provided document. This is a placeholder structure.
// You'll need to find these specifics from CHIRP or k5prog source.
//
// Conceptual DATA for read: COMMAND_BYTE_READ_EEPROM + ADDRESS_BYTES(addr) + LENGTH_BYTE(length)
func (r *Radio) ReadEEPROM(address uint16, length uint8) ([]byte, error) {
	// This is a placeholder for the actual command data construction.
	// Example: Let's assume a hypothetical read command byte 0x52
	// and address is 2 bytes (big endian), length is 1 byte.
	// commandByteRead := byte(0x52) // Hypothetical
	// commandData := make([]byte, 4)
	// commandData[0] = commandByteRead
	// binary.BigEndian.PutUint16(commandData[1:3], address)
	// commandData[3] = length

	// For now, this function is not fully implemented due to lack of specific command bytes.
	return nil, errors.New("ReadEEPROM: command structure not fully defined in this library. " +
		"Refer to CHIRP/k5prog for specific command bytes and data format.")

	// Once commandData is correctly formed:
	// response, err := r.SendCommandAndGetResponse(commandData)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to read EEPROM at 0x%04X: %w", address, err)
	// }
	// // The response should be the raw EEPROM data.
	// // Further CRC or integrity checks on the response data might be needed depending on protocol.
	// return response, nil
}

// WriteEEPROM sends a command to write data to a given EEPROM address.
// NOTE: Similar to ReadEEPROM, the exact command structure is not fully defined here.
//
// Conceptual DATA for write: COMMAND_BYTE_WRITE_EEPROM + ADDRESS_BYTES(addr) + LENGTH_BYTE(len(dataToWrite)) + dataToWrite
func (r *Radio) WriteEEPROM(address uint16, dataToWrite []byte) error {
	// This is a placeholder for the actual command data construction.
	// Example: Let's assume a hypothetical write command byte 0x57
	// commandByteWrite := byte(0x57) // Hypothetical
	// commandData := make([]byte, 0, 4+len(dataToWrite))
	// commandData = append(commandData, commandByteWrite)
	// addrBytes := make([]byte, 2)
	// binary.BigEndian.PutUint16(addrBytes, address)
	// commandData = append(commandData, addrBytes...)
	// commandData = append(commandData, byte(len(dataToWrite)))
	// commandData = append(commandData, dataToWrite...)

	return errors.New("WriteEEPROM: command structure not fully defined in this library. " +
		"Refer to CHIRP/k5prog for specific command bytes and data format.")

	// Once commandData is correctly formed:
	// _, err := r.SendCommandAndGetResponse(commandData) // Response might be an ACK/NACK
	// if err != nil {
	// 	return fmt.Errorf("failed to write EEPROM at 0x%04X: %w", address, err)
	// }
	// // Check response for success indication.
	// return nil
}

/*
Example Usage (Conceptual - requires a connected radio and correct port):

func main() {
	// Replace "/dev/ttyUSB0" with your actual serial port for the programming cable.
	// On Windows, it might be "COM3", "COM4", etc.
	// On macOS, it might be "/dev/cu.usbserial-XXXX" or similar.
	radio := quansheng_uvk5.NewRadio("/dev/ttyUSB0")
	radio.Debug = true // Enable debug output

	err := radio.Connect()
	if err != nil {
		log.Fatalf("Failed to connect to radio: %v", err)
	}
	defer radio.Disconnect()

	fmt.Println("Successfully connected to radio.")

	version, err := radio.GetFirmwareVersion()
	if err != nil {
		log.Printf("Failed to get firmware version: %v", err)
	} else {
		fmt.Printf("Radio Firmware Version: %s\n", version)
	}

	// Example of trying to read EEPROM (will fail with current placeholder)
	// To make this work, you'd need to implement the actual command bytes for ReadEEPROM.
	// eepromAddr := uint16(0x0100)
	// readLen := uint8(128)
	// data, err := radio.ReadEEPROM(eepromAddr, readLen)
	// if err != nil {
	// 	log.Printf("Failed to read EEPROM: %v", err)
	// } else {
	// 	fmt.Printf("Read %d bytes from EEPROM @ 0x%04X: %X\n", len(data), eepromAddr, data)
	// }
}

To use this library:
1. Install the serial port library: `go get go.bug.st/serial`
2. Save the code above as `quansheng_uvk5.go` in a directory (e.g., `myproject/quansheng_uvk5/`).
3. In your main Go program (e.g., `myproject/main.go`), import it:
   `import "myproject/quansheng_uvk5"` (adjust path as needed for your Go modules setup).
*/

