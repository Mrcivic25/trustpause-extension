// Pure-JS dHash Implementation using OffscreenCanvas

export async function computeDHash(dataUrl) {
    try {
        // Fetch the dataUrl to a blob
        const response = await fetch(dataUrl);
        const blob = await response.blob();
        
        // Create a bitmap from the blob
        const bitmap = await createImageBitmap(blob);
        
        // Target size for dHash is 9x8
        const width = 9;
        const height = 8;
        
        // Use OffscreenCanvas available in MV3 background workers
        const canvas = new OffscreenCanvas(width, height);
        const ctx = canvas.getContext('2d');
        
        // Draw the image onto the 9x8 canvas (browser handles resizing interpolation)
        ctx.drawImage(bitmap, 0, 0, width, height);
        
        // IMMEDIATELY discard the image buffer from memory to enforce strict privacy policy
        bitmap.close();
        
        // Get the raw pixel data
        const imageData = ctx.getImageData(0, 0, width, height);
        const data = imageData.data;
        
        // Convert to grayscale
        const grayscale = [];
        for (let i = 0; i < data.length; i += 4) {
            const r = data[i];
            const g = data[i+1];
            const b = data[i+2];
            // Standard luminance formula
            const lum = 0.299 * r + 0.587 * g + 0.114 * b;
            grayscale.push(lum);
        }
        
        // Compute difference hash
        let hashStr = '';
        for (let y = 0; y < height; y++) {
            for (let x = 0; x < width - 1; x++) {
                const left = grayscale[y * width + x];
                const right = grayscale[y * width + x + 1];
                // 1 if left pixel is brighter than right, 0 otherwise
                hashStr += (left > right ? '1' : '0');
            }
        }
        
        // Convert 64-bit binary string to 16-char Hex
        let hexHash = '';
        for (let i = 0; i < 64; i += 4) {
            const chunk = hashStr.slice(i, i + 4);
            hexHash += parseInt(chunk, 2).toString(16);
        }
        
        return hexHash;
    } catch (e) {
        console.error("Error computing dHash:", e);
        return null;
    }
}

