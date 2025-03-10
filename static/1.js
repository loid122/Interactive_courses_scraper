// Handle dropdown selection
function handleSelection() {
    const dropdown = document.getElementById("curriculumDropdown");
    const selectedValue = dropdown.value;

    if (selectedValue.startsWith("http")) {
        // Open static PDFs in a new tab
        window.open(selectedValue, '_blank');
    } else {
        // Fetch dynamic curriculum data
        sendGetRequest(selectedValue);
    }
}

// Fetch curriculum data and open a new tab with a table
async function sendGetRequest(dept) {
    try {
        const url = `/curriculum/${dept}`;
        const response = await fetch(url);

        if (!response.ok) throw new Error(`Failed to fetch: ${response.status}`);

        const data = await response.json();

        // Set the page title based on the department
        document.title = `${formatTitle(dept)} Curriculum`;

        openTableInNewTab(data, document.title);
    } catch (error) {
        console.error('Error:', error);
        alert('Failed to load curriculum. Please try again.');
    }
}

// Helper function to format the title
function formatTitle(dept) {
    return dept
        .replace('/\//g', ' ') // Replace slashes with spaces
        .replace('/_/g', ' ') // Replace underscores with spaces
        .replace('/\b\w/g', c => c.toUpperCase()); // Capitalize each word
}

// Open a new tab and populate it with tables
function openTableInNewTab(data, title) {
    const newTab = window.open('', '_blank');
    newTab.document.write(`
        <html>
        <head>
            <title>${title}</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f9f9f9;
                    margin: 0;
                    padding: 20px;
                    color: #333;
                }
                h1 {
                    text-align: center;
                    color: #007bff;
                    margin-bottom: 20px;
                }
                h2 {
                    color: #0056b3;
                    margin-top: 30px;
                    margin-bottom: 15px;
                }
                table {
                    width: 100%;
                    max-width: 800px;
                    margin: 0 auto;
                    border-collapse: collapse;
                    background-color: #fff;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                    border-radius: 8px;
                    overflow: hidden;
                }
                th, td {
                    padding: 12px 15px;
                    text-align: left;
                }
                th {
                    background-color: #007bff;
                    color: white;
                    font-weight: bold;
                }
                tr:nth-child(even) {
                    background-color: #f2f2f2;
                }
                tr:hover {
                    background-color: #e0f7ff;
                }
                .credits {
                    text-align: center;
                }
                .type {
                    text-align: center;
                    text-transform: capitalize;
                }
            </style>
        </head>
        <body>
            <h1>${title}</h1>
    `);

    Object.entries(data).forEach(([sem, courses]) => {
        newTab.document.write(`
            <h2>${sem}</h2>
            <table>
                <thead>
                    <tr>
                        <th>Code</th>
                        <th>Course</th>
                        <th class="credits">Credits</th>
                        <th class="type">Type</th>
                    </tr>
                </thead>
                <tbody>
        `);

        Object.entries(courses).forEach(([code, [name, credits, typ]]) => {
            newTab.document.write(`
                <tr>
                    <td>${code}</td>
                    <td>${name}</td>
                    <td class="credits">${credits}</td>
                    <td class="type">${typ}</td>
                </tr>
            `);
        });

        newTab.document.write(`
                </tbody>
            </table>
            <br>
        `);
    });

    newTab.document.write('</body></html>');
    newTab.document.close();
}