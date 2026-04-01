import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL =
  process.env.NEXT_PUBLIC_API_URL ||
  "https://feisty-reflection-production.up.railway.app";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();

    // Validate required fields
    if (!body.target) {
      return NextResponse.json(
        { error: "Target URL is required" },
        { status: 400 }
      );
    }

    if (!body.mode || !["recon", "audit", "redteam"].includes(body.mode)) {
      return NextResponse.json(
        { error: "Invalid scan mode. Must be recon, audit, or redteam" },
        { status: 400 }
      );
    }

    // Proxy to Railway backend
    const backendRes = await fetch(`${BACKEND_URL}/api/scans`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        target: body.target,
        mode: body.mode,
        stealth_preset: body.stealth_preset || "medium",
        max_requests: body.max_requests || 1000,
        divisions: body.divisions || [],
      }),
    });

    if (!backendRes.ok) {
      const errorText = await backendRes.text().catch(() => "Unknown error");
      return NextResponse.json(
        {
          error: `Backend returned ${backendRes.status}`,
          details: errorText,
        },
        { status: backendRes.status }
      );
    }

    const data = await backendRes.json();
    return NextResponse.json(data, { status: 201 });
  } catch (error) {
    console.error("Scan API error:", error);
    return NextResponse.json(
      {
        error: "Failed to communicate with backend",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 502 }
    );
  }
}

export async function GET() {
  try {
    const backendRes = await fetch(`${BACKEND_URL}/api/scans`, {
      headers: { "Content-Type": "application/json" },
    });

    if (!backendRes.ok) {
      return NextResponse.json(
        { error: `Backend returned ${backendRes.status}` },
        { status: backendRes.status }
      );
    }

    const data = await backendRes.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error("Scan list API error:", error);
    return NextResponse.json(
      { error: "Failed to fetch scans" },
      { status: 502 }
    );
  }
}
