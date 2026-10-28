import { Checker } from "@/components/Checker";

export default function Home() {
  return (
    <>
      <section className="intro">
        <h1>Not sure about a message? Get a second look.</h1>
        <p>
          Upload a screenshot of a text, email, or website. You’ll get a plain answer: how likely it is to be a scam, why,
          and what to do next.
        </p>
      </section>

      <Checker />

      <section className="how" id="how" aria-labelledby="how-heading">
        <h2 id="how-heading">How it works</h2>
        <div className="how-grid">
          <div>
            <h3>An AI reads the message</h3>
            <p>
              It reads the words in your screenshot the way a careful friend would, and looks for the tricks scammers use:
              rushing you, asking for gift cards or crypto, or pretending to be your bank.
            </p>
          </div>
          <div>
            <h3>Every link is checked separately</h3>
            <p>
              We look up how old each website is, whether it copies a real company’s name, and whether it’s on public lists
              of phishing sites. A link that fails these checks raises the score even if the message sounds friendly.
            </p>
          </div>
          <div>
            <h3>You get steps, not just a number</h3>
            <p>
              Each answer ends with what to do: who to call, what not to tap, and where to report it. If you already paid,
              call your bank right away.
            </p>
          </div>
        </div>
      </section>
    </>
  );
}
