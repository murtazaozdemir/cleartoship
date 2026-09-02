import pc from 'picocolors';

const ART = String.raw`
   ___ _              _____      ___ _    _
  / __| |___ __ _ _ _|_   _|__  / __| |_ (_)_ __
 | (__| / -_) _' | '_| | |/ _ \ \__ \ ' \| | '_ \
  \___|_\___\__,_|_|   |_|\___/ |___/_||_|_| .__/
                                           |_|`;

export function banner(version: string): string {
  return (
    pc.cyan(ART) +
    '\n  ' +
    pc.dim('Pre-flight security check for AI-built apps, agents included') +
    pc.dim(` • v${version}`) +
    '\n'
  );
}
