#pragma once

/* STORED DEFAULT DRIVER SYSTEM BECAUSE I DON'T SEE THE POINT OF CHANGING IT. */

void start_driver()
{
	/* Handle Driver */
	driver().handle_driver();

	/* If driver is not loaded then */
	if (!driver().is_loaded())
	{
		cout << xor_a("[+] Initializing drivers . . .") << endl;
		map_driver();
	}

	driver().handle_driver();
	driver().is_loaded() ? cout << xor_a("driver initialized!") << endl : cout << xor_a("driver initialize error =<") << endl;
}

