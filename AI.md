# AI Usage Summary

### Agents/Tools Used

    I use Cursor as my main IDE now, as I find its built-in agents and tools to
be the most effective for helping me code (in comparison to Claude Code, for instance).
In addition to this, it offers many models and modes under the same umbrella, which
I find very useful as I tend to switch models. I generally use GPT-5.2 for more
theoretical things: providing feedback on design decisions, learning a new codebase,
evaluating code, etc. For actual code generation, I prefer Claude Sonnet 4.5.

### Approach

    My approach to using AI for this project had a steep learning curve. Having
now worked with AI in a couple different codebases, it seems imperative to learn
how to leverage AI tools for the specific codebase you're working on. LLMs behave
very differently working on different languages, technologies, and even design
architectures. I have to take a different approach when prompting for work on a
microservices architecture versus an authentication framework like this. That being
said, I had to lean on the agent more than I would've liked given my unfamiliarity
with Typescript and Fastify. I first used it to understand the codebase and which
pieces did what. I attempted to generate tests for the new features first, then
use very specific prompting which provided as much context as possible to get it
to do the heavy lifting of writing the implementation. I would consult with GPT-5.2
both before and after implementation to get feedback on my design choices and evaluate
whether the feature checked all the boxes from the instructions. Given that I have
no-one to review my code for this, I found this feedback incredibly helpful.

### What Went Well

    LLMs never fail to impress me with their ability to generate comprehensive
unit tests in a single shot. Before this project, I had not written a single line
of Typsecript outside of a tutorial. I had no idea about testing idioms, and utilizing
the AI to create boilerplate and implement tests saved what would have surely been
many hours. It was particularly helpful when generating the demo auth server, and
provided a very capable test demo on the frist try. Of course, all of this generated
code needed tweaking. It often created redundant tests or ones which didn't actually
test the feature they applied to.
    The AI was also a wonderful help in updating documentation. As always, it generally
put too much information, but I find it much easier to trim down than to write
the content of the README myself. There's definitely a skill to writing good documentation,
though, and if I were doing regular work in this codebase I would certainly put
much more effort into deeply understanding the content and condensing it better
in the docs.

### What Didn't Go Well

    The AI was not very good at implementing the features I was asking for, nor
at maintaining backwards compatibility for the old `authorize()` method. I found
that it would routinely do something which would work, but would just be bad coding
practice, such as setting class-scoped variables to pass information that could
be returned by a function, or not following coding precedence set by the codebase.
This is generally to be expected, but I found the experience more frustrating and
difficult to overcome given my lack of experience in this repo, with Typescript,
and with auth backend as a whole.
