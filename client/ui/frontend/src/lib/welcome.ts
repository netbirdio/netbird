const ART = `
    _   __     __  ____  _          __   ______          __    __  __
   / | / /__  / /_/ __ )(_)________/ /  / ____/___ ___  / /_  / / / /
  /  |/ / _ \\/ __/ __  / / ___/ __  /  / / __/ __ \`__ \\/ __ \\/ /_/ /
 / /|  /  __/ /_/ /_/ / / /  / /_/ /  / /_/ / / / / / / /_/ / __  /
/_/ |_/\\___/\\__/_____/_/_/   \\__,_/   \\____/_/ /_/ /_/_.___/_/ /_/
`;

export function welcome() {
    const message = `%c${ART}%c
NetBird — The Only Secure Access Platform You'll Ever Need.

WEBSITE:      https://netbird.io/
WE'RE HIRING: https://netbird.io/careers
OPEN SOURCE:  https://github.com/netbirdio/netbird
`;

    // Intentional NetBird ASCII banner in the devtools console.
    // eslint-disable-next-line no-console
    console.log(
        message,
        "color: #f68330; font-family: monospace; font-weight: normal; line-height: 1;",
        "color: #f5f5f5; font-family: monospace; font-weight: normal; line-height: 1.4;",
    );
}
