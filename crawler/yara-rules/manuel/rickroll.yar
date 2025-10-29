rule Rickroll_Detect
{
    strings:
        $rick = "youtube.com/watch?v=dQw4w9WgXcQ"
        $meta = "no-referrer"
    condition:
        all of them
}
