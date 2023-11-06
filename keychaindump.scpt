(*
Script Name: Keychain Item Dumper
Description: This script interfaces with the macOS Keychain to extract and display all stored items.
             It covers generic passwords, internet passwords, certificates, keys, and identities.
             The script outputs the results in a dialog box and logs errors to the console.
Frameworks: Foundation, Security
*)

use framework "Foundation"
use framework "Security"
use scripting additions

-- Keychain item class constants
property kSecClass : a reference to current application's kSecClass
property kSecMatchLimit : a reference to current application's kSecMatchLimit
property kSecReturnAttributes : a reference to current application's kSecReturnAttributes
property kSecReturnData : a reference to current application's kSecReturnData
property kSecMatchLimitAll : a reference to current application's kSecMatchLimitAll
property kSecClassGenericPassword : a reference to current application's kSecClassGenericPassword
property kSecClassInternetPassword : a reference to current application's kSecClassInternetPassword
property kSecClassCertificate : a reference to current application's kSecClassCertificate
property kSecClassKey : a reference to current application's kSecClassKey
property kSecClassIdentity : a reference to current application's kSecClassIdentity
property kSecAttrAccessible : a reference to current application's kSecAttrAccessible

-- Logs messages to the console or displays them in a dialog box
on logToConsole(message)
	try
		display dialog message buttons {"OK"} default button "OK"
	on error dialogError
		-- Logs to the system log if the dialog fails to display
		do shell script "logger AppleScript dialog failed: " & quoted form of dialogError
	end try
end logToConsole

-- Searches the Keychain and compiles a list of all items
on searchKeychain()
	logToConsole("Starting searchKeychain")
	set keychainClasses to {kSecClassGenericPassword, kSecClassInternetPassword, kSecClassCertificate, kSecClassKey, kSecClassIdentity}
	set output to {}
	
	-- Iterates over each Keychain item class
	repeat with aClass in keychainClasses
		set query to {kSecClass:aClass, kSecMatchLimit:kSecMatchLimitAll, kSecReturnAttributes:true, kSecReturnData:true}
		logToConsole("Query dictionary set up for class " & (aClass as string))
		
		-- Attempts to match Keychain items based on the query
		try
			set searchResults to current application's SecItemCopyMatching(query, reference)
			logToConsole("Search completed for class " & (aClass as string))
			
			-- Processes each found item
			if (searchResults is not missing value) and (class of searchResults is list) then
				logToConsole("Search results are valid and a list for class " & (aClass as string))
				
				-- Extracts data from each item
				repeat with anItem in searchResults
					delay 0.1 -- Introduce a slight delay to prevent system resource overload
					logToConsole("Processing an item for class " & (aClass as string))
					try
						if (anItem is not missing value) and (class of anItem is record) then
							set itemDict to anItem as record
							logToConsole("Item converted to record for class " & (aClass as string))
							
							-- Retrieves the password or secret data
							set theSecret to my safeDataToString(itemDict's kSecValueData)
							if theSecret is not missing value then
								logToConsole("Secret data is valid for class " & (aClass as string))
								set end of output to {class:aClass, attributes:itemDict, secret:theSecret}
								logToConsole("Secret data added to output for class " & (aClass as string))
							else
								logToConsole("Secret data is missing value for class " & (aClass as string))
								set end of output to {class:aClass, attributes:itemDict, secret:"[Secret data unreadable]"}
							end if
						else
							logToConsole("An item is missing value or not a record for class " & (aClass as string))
						end if
					on error innerError number innerNumber
						logToConsole("Error processing an item for class " & (aClass as string) & ": " & innerError & " (" & innerNumber & ")")
						set end of output to {class:aClass, errorMessage:innerError, errorCode:innerNumber}
					end try
				end repeat
			else
				logToConsole("No items found or searchResults is not a list for class " & (aClass as string))
			end if
		on error errorMessage number errorNumber
			logToConsole("Search failed for class " & (aClass as string) & ": " & errorMessage & " (" & errorNumber & ")")
		end try
	end repeat
	
	logToConsole("Returning output")
	return output
end searchKeychain

-- Converts NSData to a string representation
on safeDataToString(theData)
	try
		if theData is not missing value then
			set theString to (current application's NSString's alloc()'s initWithData:theData encoding:(current application's NSUTF8StringEncoding))
			if theString is not missing value then
				return theString as text
			else
				return missing value
			end if
		else
			return missing value
		end if
	on error error_message number error_number
		logToConsole("Error converting data to string: " & error_message & " (" & error_number & ")")
		return missing value
	end try
end safeDataToString

-- Main handler to start the Keychain search and handle any errors
try
	logToConsole("Starting test handler")
	set searchResult to searchKeychain()
	logToConsole("Search result: " & searchResult)
on error finalError number finalNumber
	logToConsole("Final error: " & finalError & " (" & finalNumber & ")")
end try
